"use strict";

const script = document.currentScript;
const token = script?.dataset.recoveryToken || "";
const form = document.querySelector("#recovery-form");
const usernameInput = document.querySelector("#recovery-username");
const statusOutput = document.querySelector("#recovery-status");
const submitButton = form.querySelector("button");

form.addEventListener("submit", registerAdministrator);

async function registerAdministrator(event) {
  event.preventDefault();
  if (!window.isSecureContext || !window.PublicKeyCredential) {
    setStatus("请使用 HTTPS 或 localhost，并使用支持 Passkey 的浏览器", "error");
    return;
  }
  submitButton.disabled = true;
  setStatus("等待浏览器 Passkey 操作...", "muted");
  try {
    const { publicKey } = await postJson(`/${token}/options`, {
      username: usernameInput.value.trim(),
    });
    const credential = await navigator.credentials.create({
      publicKey: decodeCreationOptions(publicKey),
    });
    const result = await postJson(`/${token}/verify`, {
      credential: encodeRegistrationCredential(credential),
    });
    setStatus("管理员已创建", "success");
    window.location.replace(result.redirectUrl || "/management");
  } catch (error) {
    if (
      error instanceof DOMException &&
      ["AbortError", "NotAllowedError", "TimeoutError"].includes(error.name)
    ) {
      setStatus("Passkey 注册已取消", "muted");
    } else {
      setStatus(error.message || String(error), "error");
    }
  } finally {
    submitButton.disabled = false;
  }
}

async function postJson(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(data.error || "请求失败");
  }
  return data;
}

function decodeCreationOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    user: { ...options.user, id: base64urlToBuffer(options.user.id) },
    excludeCredentials: (options.excludeCredentials || []).map((item) => ({
      ...item,
      id: base64urlToBuffer(item.id),
    })),
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
      transports: response.getTransports ? response.getTransports() : [],
    },
    clientExtensionResults: credential.getClientExtensionResults(),
  };
}

function base64urlToBuffer(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64.padEnd(base64.length + ((4 - (base64.length % 4)) % 4), "=");
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0)).buffer;
}

function bufferToBase64url(buffer) {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function setStatus(message, kind) {
  statusOutput.hidden = false;
  statusOutput.textContent = message;
  statusOutput.dataset.kind = kind;
}
