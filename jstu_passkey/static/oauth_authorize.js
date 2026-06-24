"use strict";

const ACTION_TOKEN_STORAGE_KEY = "passkey-action-token";
const root = document.querySelector("[data-oauth-authorize]");
const logoButton = document.querySelector("#oauth-logo-button");
const statusOutput = document.querySelector("#oauth-status");
const STATUS_AUTO_HIDE_MS = 10000;

let authorizationInFlight = false;
let statusHideTimer = 0;

logoButton?.addEventListener("click", authorizeWithPasskey);
authorizeWithPasskey();

async function authorizeWithPasskey() {
  if (authorizationInFlight) {
    return;
  }

  if (!canUsePasskey()) {
    setStatus(passkeyUnavailableMessage(), "error");
    return;
  }

  authorizationInFlight = true;
  logoButton.disabled = true;
  setStatus("等待浏览器 Passkey 操作...", "muted", { autoHide: false });
  try {
    const { publicKey } = await postJson("/auth/passkey/options", {
      username: root.dataset.username || "",
      mode: root.dataset.oauthMode,
      authFlowToken: root.dataset.authFlowToken,
    });
    const assertion = await navigator.credentials.get({
      publicKey: decodeRequestOptions(publicKey),
    });
    const verification = await postJson("/auth/passkey/verify", {
      credential: encodeAuthenticationCredential(assertion),
      authFlowToken: root.dataset.authFlowToken,
    });
    if (verification.action_token) {
      window.sessionStorage.setItem(
        ACTION_TOKEN_STORAGE_KEY,
        verification.action_token,
      );
    }
    let result;
    if (root.dataset.oauthMode === "challenge") {
      result = await postJson(
        `/oauth/challenge/${encodeURIComponent(root.dataset.challengeId)}/complete`,
        {},
      );
    } else if (root.dataset.oauthMode === "code") {
      result = await postJson("/oauth/authorize/complete", {
        client_id: root.dataset.clientId,
        redirect_uri: root.dataset.redirectUri,
        state: root.dataset.state,
      });
    } else {
      result = { redirectUrl: root.dataset.returnTo || "/" };
    }
    window.location.assign(result.redirectUrl);
  } catch (error) {
    if (root.dataset.oauthMode === "code" && root.dataset.errorRedirectUri) {
      const target = new URL(root.dataset.errorRedirectUri);
      target.searchParams.set(
        "error",
        isPasskeyCancelError(error) ? "access_denied" : "authentication_failed",
      );
      target.searchParams.set(
        "error_description",
        isPasskeyCancelError(error)
          ? "Passkey 验证已取消"
          : error.message || String(error),
      );
      target.searchParams.set("state", root.dataset.state);
      window.location.assign(target);
      return;
    }
    if (isPasskeyCancelError(error)) {
      setStatus("Passkey 验证已取消", "muted");
    } else {
      setStatus(error.message || String(error), "error");
    }
    logoButton.disabled = false;
    authorizationInFlight = false;
  }
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
  statusOutput.hidden = false;
  statusOutput.textContent = message;
  statusOutput.className = "status";
  statusOutput.dataset.kind = kind || "";

  if (options.autoHide === false) {
    return;
  }

  statusHideTimer = window.setTimeout(() => {
    statusOutput.hidden = true;
    statusOutput.textContent = "";
    statusOutput.dataset.kind = "";
  }, STATUS_AUTO_HIDE_MS);
}
