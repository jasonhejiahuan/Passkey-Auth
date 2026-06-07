"use strict";

const logoButton = document.querySelector("#logo-button");
const statusOutput = document.querySelector("#status");
const STATUS_AUTO_HIDE_MS = 10000;

let logoPrimaryClickCount = 0;
let logoPrimaryClickTimer = 0;
let logoSecondaryClickCount = 0;
let logoSecondaryClickTimer = 0;
let registerModule = null;
let registerPanelClosing = false;
let statusHideTimer = 0;

logoButton.addEventListener("click", handleLogoClick);
logoButton.addEventListener("pointerdown", handleLogoPointerDown);
logoButton.addEventListener("contextmenu", blockLogoContextMenu);
document.addEventListener("pointerdown", handleOutsidePointerDown);
document.addEventListener("keydown", handleShortcut);

refreshSession();

function handleLogoClick() {
  logoPrimaryClickCount += 1;
  window.clearTimeout(logoPrimaryClickTimer);

  if (logoPrimaryClickCount >= 5) {
    logoPrimaryClickCount = 0;
    loginWithoutUsername();
    return;
  }

  logoPrimaryClickTimer = window.setTimeout(() => {
    logoPrimaryClickCount = 0;
  }, 520);
}

function handleLogoPointerDown(event) {
  if (event.button !== 2) {
    return;
  }

  logoSecondaryClickCount += 1;
  window.clearTimeout(logoSecondaryClickTimer);

  if (logoSecondaryClickCount >= 5) {
    logoSecondaryClickCount = 0;
    unlockRegisterPanel();
    return;
  }

  logoSecondaryClickTimer = window.setTimeout(() => {
    logoSecondaryClickCount = 0;
  }, 1400);
}

function blockLogoContextMenu(event) {
  event.preventDefault();
}

function handleShortcut(event) {
  const key = event.key.toLowerCase();
  const command = event.metaKey || event.ctrlKey;

  if (command && event.shiftKey && key === "k") {
    event.preventDefault();
    toggleRegisterPanel();
    return;
  }

  if (event.altKey && key === "r") {
    event.preventDefault();
    toggleRegisterPanel();
    return;
  }

  if (command && key === "k") {
    event.preventDefault();
    loginWithoutUsername();
    return;
  }

  if (event.key === "Escape" && registerModule?.isVisible()) {
    hideRegisterPanelWithTransition();
  }
}

function handleOutsidePointerDown(event) {
  if (!registerModule?.isVisible()) {
    return;
  }

  const form = document.querySelector("#passkey-form");
  if (!form) {
    return;
  }

  const target = event.target;
  if (form.contains(target) || logoButton.contains(target)) {
    return;
  }

  event.preventDefault();
  hideRegisterPanelWithTransition();
}

async function unlockRegisterPanel() {
  await runPasskeyAction(
    async () => {
      const { register } = await postJson(apiPath("ui", "intent"), {
        intent: "register",
      });
      registerModule = await import(register.clientPath);
      register.motion = canUseViewTransition() ? "view-transition" : "css";
      await updateRegisterPanelWithTransition(() => {
        registerModule.revealRegisterPanel(register);
      });
    },
    { requireWebAuthn: false, revealStatus: false },
  );
}

function toggleRegisterPanel() {
  if (registerModule?.isVisible()) {
    hideRegisterPanelWithTransition();
  } else {
    unlockRegisterPanel();
  }
}

async function hideRegisterPanelWithTransition() {
  if (!registerModule?.isVisible() || registerPanelClosing) {
    return;
  }

  registerPanelClosing = true;
  try {
    await hideRegisterPanelWithCssFallback();
  } finally {
    registerPanelClosing = false;
  }
}

async function updateRegisterPanelWithTransition(update) {
  if (!canUseViewTransition()) {
    update();
    return;
  }

  const transition = document.startViewTransition(update);
  await transition.finished;
}

async function hideRegisterPanelWithCssFallback() {
  const form = document.querySelector("#passkey-form");
  if (!form || window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    registerModule.hideRegisterPanel();
    return;
  }

  await new Promise((resolve) => {
    let settled = false;
    const finish = () => {
      if (settled) {
        return;
      }
      settled = true;
      form.removeEventListener("animationend", handleAnimationEnd);
      resolve();
    };
    const handleAnimationEnd = (event) => {
      if (event.target === form && event.animationName === "register-sheet-out") {
        finish();
      }
    };

    form.addEventListener("animationend", handleAnimationEnd);
    form.classList.remove("is-closing");
    form.offsetWidth;
    form.classList.add("is-closing");
    window.setTimeout(finish, 260);
  });
  registerModule.hideRegisterPanel();
  form.classList.remove("is-closing");
}

function canUseViewTransition() {
  return (
    Boolean(document.startViewTransition) &&
    !window.matchMedia("(prefers-reduced-motion: reduce)").matches
  );
}

async function loginWithPasskey(options = {}) {
  await runPasskeyAction(async () => {
    const username = options.username ?? "";
    const { publicKey } = await postJson(apiPath("login", "options"), { username });
    const assertion = await navigator.credentials.get({
      publicKey: decodeRequestOptions(publicKey),
    });

    const payload = { credential: encodeAuthenticationCredential(assertion) };
    await postJson(apiPath("login", "verify"), payload);
    setStatus("登录成功", "success");
  });
}

async function loginWithoutUsername() {
  await loginWithPasskey({ username: "" });
}

async function refreshSession() {
  const response = await fetch(apiPath("me"));
  const data = await response.json();
  if (data.authenticated) {
    setStatus("当前已登录", "success");
  } else {
    statusOutput.hidden = true;
  }
}

async function runPasskeyAction(action, options = {}) {
  if (options.requireWebAuthn !== false && !window.PublicKeyCredential) {
    setStatus("当前浏览器不支持 WebAuthn / Passkey", "error");
    return;
  }

  if (options.revealStatus !== false) {
    setStatus("等待浏览器 Passkey 操作...", "muted", { autoHide: false });
  }
  try {
    await action();
  } catch (error) {
    if (isPasskeyCancelError(error)) {
      setStatus("Passkey 登录已取消", "muted");
      return;
    }
    setStatus(error.message || String(error), "error");
  }
}

function apiPath(...segments) {
  return `/api/${segments.join("/")}`;
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await readJsonResponse(response);
  if (!response.ok) {
    throw new Error(data.error || "请求失败");
  }
  return data;
}

async function readJsonResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }

  const text = await response.text();
  const fallback = text ? text.slice(0, 160) : response.statusText;
  return {
    ok: false,
    error: `服务器返回了非 JSON 响应：${response.status} ${fallback}`,
  };
}

function decodeRequestOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map(decodeDescriptor),
  };
}

function decodeDescriptor(descriptor) {
  return {
    ...descriptor,
    id: base64urlToBuffer(descriptor.id),
  };
}

function encodeAuthenticationCredential(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || null,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      authenticatorData: bufferToBase64url(response.authenticatorData),
      signature: bufferToBase64url(response.signature),
      userHandle: response.userHandle
        ? bufferToBase64url(response.userHandle)
        : null,
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

function base64urlToBuffer(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes.buffer;
}

function bufferToBase64url(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function isPasskeyCancelError(error) {
  return (
    error instanceof DOMException &&
    ["AbortError", "NotAllowedError", "TimeoutError"].includes(error.name)
  );
}

function setStatus(message, kind, options = {}) {
  window.clearTimeout(statusHideTimer);
  statusOutput.hidden = false;
  statusOutput.textContent = message;
  statusOutput.dataset.kind = kind;

  if (options.autoHide === false) {
    return;
  }

  statusHideTimer = window.setTimeout(() => {
    statusOutput.hidden = true;
    statusOutput.textContent = "";
    statusOutput.dataset.kind = "";
  }, STATUS_AUTO_HIDE_MS);
}
