"use strict";

(() => {
  const trigger = document.querySelector("#account-passkeys-button");
  const dialog = document.querySelector("#account-passkeys-dialog");
  if (!trigger || !dialog) return;
  const list = dialog.querySelector("#account-passkeys-list");
  const add = dialog.querySelector("#account-passkeys-add");
  const authenticator = dialog.querySelector("#account-passkeys-authenticator");
  const status = dialog.querySelector("#account-passkeys-status");
  let csrfToken = "";
  let operation = null;
  let generation = 0;

  function showStatus(message = "", kind = "") {
    status.textContent = message;
    status.dataset.kind = kind;
    status.hidden = !message;
  }
  async function request(url, data, signal) {
    const response = await fetch(url, {
      method: data === undefined ? "GET" : "POST",
      credentials: "same-origin",
      ...(data === undefined ? {} : {
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      }),
      signal,
    });
    const result = await response.json();
    if (!response.ok) {
      const error = new Error(result.error || "操作未完成，请重试");
      error.reauthRequired = result.reauthRequired === true;
      throw error;
    }
    return result;
  }
  function decode(value) {
    const source = value.replace(/-/g, "+").replace(/_/g, "/");
    return Uint8Array.from(atob(source.padEnd(Math.ceil(source.length / 4) * 4, "=")), c => c.charCodeAt(0));
  }
  function encode(value) {
    return btoa(String.fromCharCode(...new Uint8Array(value)))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function descriptors(values = []) {
    return values.map(value => ({ ...value, id: decode(value.id) }));
  }
  async function reauthenticate(signal) {
    showStatus("验证当前 Passkey");
    const { authFlowToken } = await request("/auth/passkey/flow", {}, signal);
    const { publicKey } = await request("/auth/passkey/options", { mode: "reauth", authFlowToken }, signal);
    const credential = await navigator.credentials.get({
      publicKey: { ...publicKey, challenge: decode(publicKey.challenge), allowCredentials: descriptors(publicKey.allowCredentials) },
      signal,
    });
    if (!credential) throw new DOMException("Cancelled", "AbortError");
    const r = credential.response;
    const result = await request("/auth/passkey/verify", {
      authFlowToken,
      credential: {
        id: credential.id, rawId: encode(credential.rawId), type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment || null,
        response: {
          clientDataJSON: encode(r.clientDataJSON), authenticatorData: encode(r.authenticatorData),
          signature: encode(r.signature), userHandle: r.userHandle ? encode(r.userHandle) : null,
        },
        clientExtensionResults: credential.getClientExtensionResults(),
      },
    }, signal);
    if (result.action_token) {
      sessionStorage.setItem("passkey-action-token", result.action_token);
      document.dispatchEvent(new CustomEvent("passkey-reauthenticated"));
    }
  }
  async function refresh(signal) {
    const data = await request("/api/account/passkeys", undefined, signal);
    csrfToken = data.csrfToken;
    const entries = data.passkeys.map(key => {
      const entry = document.createElement("li");
      entry.dataset.passkeyId = key.id;
      const title = document.createElement("strong");
      title.textContent = `Passkey #${key.id}`;
      const state = document.createElement("span");
      state.textContent = key.disabledAt !== null ? "已停用" : key.backedUp ? "已同步" : "已启用";
      const date = document.createElement("time");
      const created = new Date(key.createdAt * 1000);
      date.dateTime = created.toISOString();
      date.textContent = created.toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });
      entry.append(title, state, date);
      return entry;
    });
    list.replaceChildren(...entries);
  }
  trigger.addEventListener("click", async () => {
    if (dialog.open) return;
    operation?.abort();
    const turn = ++generation;
    operation = new AbortController();
    const { signal } = operation;
    csrfToken = "";
    list.replaceChildren();
    showStatus();
    add.disabled = true;
    authenticator.disabled = true;
    dialog.showModal();
    try {
      await refresh(signal);
    } catch (error) {
      if (!signal.aborted && turn === generation) showStatus(error.message, "error");
    } finally {
      if (turn === generation) {
        add.disabled = !csrfToken;
        authenticator.disabled = false;
      }
    }
  });
  function close() {
    ++generation;
    operation?.abort();
    operation = null;
    csrfToken = "";
    add.disabled = false;
    authenticator.disabled = false;
    showStatus();
    if (dialog.open) dialog.close();
  }
  dialog.querySelector("#account-passkeys-close").addEventListener("click", close);
  dialog.addEventListener("cancel", event => { event.preventDefault(); close(); });
  dialog.addEventListener("close", () => { operation?.abort(); });
  add.addEventListener("click", async () => {
    if (add.disabled || !csrfToken) return;
    if (!window.isSecureContext || !window.PublicKeyCredential) {
      showStatus("当前浏览器无法使用 Passkey", "error");
      return;
    }
    const turn = ++generation;
    operation?.abort();
    operation = new AbortController();
    const { signal } = operation;
    add.disabled = true;
    authenticator.disabled = true;
    showStatus();
    try {
      let options;
      try {
        options = await request("/api/account/passkeys/options", { csrfToken, ...(authenticator.value ? { authenticator: authenticator.value } : {}) }, signal);
      } catch (error) {
        if (!error.reauthRequired) throw error;
        await reauthenticate(signal);
        options = await request("/api/account/passkeys/options", { csrfToken, ...(authenticator.value ? { authenticator: authenticator.value } : {}) }, signal);
      }
      showStatus("创建新的 Passkey");
      const publicKey = options.publicKey;
      const credential = await navigator.credentials.create({
        publicKey: {
          ...publicKey, challenge: decode(publicKey.challenge),
          user: { ...publicKey.user, id: decode(publicKey.user.id) },
          excludeCredentials: descriptors(publicKey.excludeCredentials),
        },
        signal,
      });
      if (!credential) throw new DOMException("Cancelled", "AbortError");
      await request("/api/account/passkeys/verify", {
        csrfToken,
        credential: {
          id: credential.id, rawId: encode(credential.rawId), type: credential.type,
          authenticatorAttachment: credential.authenticatorAttachment || null,
          response: {
            clientDataJSON: encode(credential.response.clientDataJSON),
            attestationObject: encode(credential.response.attestationObject),
            transports: credential.response.getTransports?.() || [],
          },
          clientExtensionResults: credential.getClientExtensionResults(),
        },
      }, signal);
      await refresh(signal);
      if (turn === generation) {
        showStatus("Passkey 已添加");
        document.dispatchEvent(new CustomEvent("passkey-credentials-changed"));
      }
    } catch (error) {
      if (signal.aborted || turn !== generation) return;
      const cancelled = ["AbortError", "NotAllowedError", "TimeoutError"].includes(error.name);
      const duplicate = error.name === "InvalidStateError";
      showStatus(cancelled ? "已取消" : duplicate ? "此认证器已保存当前账号的 Passkey" : error.message, cancelled ? "" : "error");
    } finally {
      if (turn === generation) {
        add.disabled = false;
        authenticator.disabled = false;
      }
    }
  });
})();
