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
let authenticatedUser = null;
let sessionReady = false;
let sessionActionInProgress = false;

logoButton.addEventListener("click", handleLogoClick);
logoButton.addEventListener("pointerdown", handleLogoPointerDown);
logoButton.addEventListener("contextmenu", blockLogoContextMenu);
document.addEventListener("pointerdown", handleOutsidePointerDown);
document.addEventListener("keydown", handleShortcut);
document.addEventListener("passkey-session-changed", handleSessionChanged);

refreshSession();

function handleSessionChanged() {
  refreshSession({ refreshNonHome: true });
}

function handleLogoClick() {
  logoPrimaryClickCount += 1;
  window.clearTimeout(logoPrimaryClickTimer);

  if (logoPrimaryClickCount >= 5) {
    logoPrimaryClickCount = 0;
    handlePrimaryLogoAction();
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
    handleSecondaryLogoAction();
    return;
  }

  logoSecondaryClickTimer = window.setTimeout(() => {
    logoSecondaryClickCount = 0;
  }, 1400);
}

function blockLogoContextMenu(event) {
  event.preventDefault();
}

async function handlePrimaryLogoAction() {
  await ensureSessionReady();
  if (authenticatedUser) {
    await logout();
    return;
  }
  await loginWithoutUsername();
}

async function handleSecondaryLogoAction() {
  await ensureSessionReady();
  if (authenticatedUser) {
    await logout();
    return;
  }
  await unlockRegisterPanel();
}

async function handleShortcut(event) {
  const key = event.key.toLowerCase();
  const command = event.metaKey || event.ctrlKey;
  const isAuthShortcut = (
    (command && key === "k") ||
    (event.altKey && key === "r")
  );

  if (isAuthShortcut) {
    await ensureSessionReady();
  }

  if (command && event.shiftKey && key === "k") {
    event.preventDefault();
    if (authenticatedUser) {
      showAuthenticatedStatus();
      return;
    }
    toggleRegisterPanel();
    return;
  }

  if (event.altKey && key === "r") {
    event.preventDefault();
    if (authenticatedUser) {
      showAuthenticatedStatus();
      return;
    }
    toggleRegisterPanel();
    return;
  }

  if (command && key === "k") {
    event.preventDefault();
    if (authenticatedUser) {
      showAuthenticatedStatus();
      return;
    }
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
  await ensureSessionReady();
  if (authenticatedUser) {
    showAuthenticatedStatus();
    return;
  }
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
  if (authenticatedUser) {
    showAuthenticatedStatus();
    return;
  }
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
  await ensureSessionReady();
  if (authenticatedUser) {
    showAuthenticatedStatus();
    return;
  }
  const returnTo = `${window.location.pathname}${window.location.search}${window.location.hash}`;
  const query = new URLSearchParams({ return_to: returnTo });
  window.location.assign(`/auth/passkey?${query}`);
}

async function loginWithoutUsername() {
  await loginWithPasskey({ username: "" });
}

async function refreshSession(options = {}) {
  try {
    const response = await fetch(apiPath("me"));
    const data = await readJsonResponse(response);
    if (!response.ok) {
      throw new Error(data.error || "无法检查登录状态");
    }
    authenticatedUser = data.authenticated ? data.user : null;
    if (authenticatedUser) {
      if (options.refreshNonHome && !isHomePage()) {
        window.location.reload();
        return;
      }
      if (registerModule?.isVisible()) {
        await hideRegisterPanelWithTransition();
      }
      if (isHomePage() && statusOutput.dataset.persistent !== "true") {
        showAuthenticatedStatus();
      }
    } else if (statusOutput.dataset.persistent !== "true") {
      window.clearTimeout(statusHideTimer);
      statusOutput.hidden = true;
      statusOutput.textContent = "";
      statusOutput.dataset.kind = "";
    }
  } catch (error) {
    authenticatedUser = null;
    setStatus(error.message || String(error), "error");
  } finally {
    sessionReady = true;
  }
}

async function ensureSessionReady() {
  if (!sessionReady) {
    await refreshSession();
  }
}

function isHomePage() {
  return window.location.pathname === "/";
}

function showAuthenticatedStatus() {
  if (
    !authenticatedUser ||
    !isHomePage() ||
    statusOutput.dataset.persistent === "true"
  ) {
    return;
  }
  setStatus(`当前已登录 · ${authenticatedUser.username}`, "success", {
    autoHide: false,
  });
}

async function logout() {
  if (!authenticatedUser || sessionActionInProgress) {
    return;
  }

  sessionActionInProgress = true;
  try {
    if (registerModule?.isVisible()) {
      await hideRegisterPanelWithTransition();
    }
    await postJson(apiPath("logout"), {});
    authenticatedUser = null;
    setStatus("已退出登录", "success");
  } catch (error) {
    setStatus(error.message || String(error), "error");
    window.setTimeout(showAuthenticatedStatus, STATUS_AUTO_HIDE_MS);
  } finally {
    sessionActionInProgress = false;
  }
}

async function runPasskeyAction(action, options = {}) {
  if (options.requireWebAuthn !== false && !canUsePasskey()) {
    setStatus(passkeyUnavailableMessage(), "error");
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

function canUsePasskey() {
  return window.isSecureContext && Boolean(window.PublicKeyCredential);
}

function passkeyUnavailableMessage() {
  if (!window.isSecureContext) {
    return "当前连接不是安全上下文，请使用 HTTPS 或 localhost 打开后再使用 Passkey";
  }
  return "当前浏览器不支持 WebAuthn / Passkey";
}

function setStatus(message, kind, options = {}) {
  window.clearTimeout(statusHideTimer);
  delete statusOutput.dataset.persistent;
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
