REGISTER_CLIENT_JS = r'''
const statusOutput = document.querySelector("#status");
const STATUS_AUTO_HIDE_MS = 10000;

let passkeyForm = null;
let usernameInput = null;
let registerButton = null;
let statusHideTimer = 0;

export function isVisible() {
  return Boolean(passkeyForm && !passkeyForm.hidden);
}

export function hideRegisterPanel() {
  if (!passkeyForm) {
    return;
  }
  passkeyForm.hidden = true;
  if (!statusOutput.dataset.kind || statusOutput.dataset.kind === "muted") {
    statusOutput.hidden = true;
  }
}

export function revealRegisterPanel(config) {
  ensureRegisterPanel(config);
  passkeyForm.dataset.motion = config.motion || "css";
  passkeyForm.hidden = false;
  statusOutput.hidden = true;
  usernameInput.focus({ preventScroll: true });
}

function ensureRegisterPanel(config) {
  if (passkeyForm) {
    return;
  }

  document.querySelector("#passkey-form")?.remove();

  passkeyForm = document.createElement("form");
  passkeyForm.id = "passkey-form";
  passkeyForm.className = "form";
  passkeyForm.hidden = true;

  const label = document.createElement("label");
  label.htmlFor = "username";
  label.textContent = "用户名";

  usernameInput = document.createElement("input");
  usernameInput.id = "username";
  usernameInput.name = "username";
  usernameInput.autocomplete = "username webauthn";
  usernameInput.maxLength = config.usernameMaxLength || 64;
  usernameInput.placeholder = config.usernamePlaceholder || "用户名";

  const actions = document.createElement("div");
  actions.className = "actions";

  registerButton = document.createElement("button");
  registerButton.className = "primary";
  registerButton.type = "button";
  registerButton.textContent = config.buttonText || "注册";
  registerButton.addEventListener("click", registerPasskey);

  actions.append(registerButton);
  passkeyForm.append(label, usernameInput, actions);
  statusOutput.before(passkeyForm);
}

async function registerPasskey() {
  await runRegisterAction(async () => {
    const username = getUsername();
    const { publicKey } = await postJson("/api/register/options", {
      username,
    });
    const credential = await navigator.credentials.create({
      publicKey: decodeCreationOptions(publicKey),
    });

    const payload = { credential: encodeRegistrationCredential(credential) };
    await postJson("/api/register/verify", payload);
    setStatus("已注册并登录", "success");
  });
}

async function runRegisterAction(action) {
  if (!canUsePasskey()) {
    setStatus(passkeyUnavailableMessage(), "error");
    return;
  }

  registerButton.disabled = true;
  setStatus("等待浏览器 Passkey 操作...", "muted", { autoHide: false });
  try {
    await action();
  } catch (error) {
    if (isPasskeyCancelError(error)) {
      setStatus("Passkey 注册已取消", "muted");
      return;
    }
    setStatus(error.message || String(error), "error");
  } finally {
    registerButton.disabled = false;
  }
}

function getUsername() {
  const username = usernameInput.value.trim();
  if (!username) {
    throw new Error("请输入用户名");
  }
  return username;
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

function decodeCreationOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: {
      ...options.user,
      id: base64urlToBuffer(options.user.id),
    },
    excludeCredentials: (options.excludeCredentials || []).map(decodeDescriptor),
  };
}

function decodeDescriptor(descriptor) {
  return {
    ...descriptor,
    id: base64urlToBuffer(descriptor.id),
  };
}

function encodeRegistrationCredential(credential) {
  const response = credential.response;
  return {
    id: credential.id,
    rawId: bufferToBase64url(credential.rawId),
    type: credential.type,
    authenticatorAttachment: credential.authenticatorAttachment || null,
    response: {
      clientDataJSON: bufferToBase64url(response.clientDataJSON),
      attestationObject: bufferToBase64url(response.attestationObject),
      transports: typeof response.getTransports === "function"
        ? response.getTransports()
        : [],
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
'''
