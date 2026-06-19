"use strict";

const csrfToken = document.querySelector('meta[name="management-csrf-token"]').content;
const statusOutput = document.querySelector("#management-status");
const dialog = document.querySelector("#editor-dialog");
const editorTitle = document.querySelector("#editor-title");
const editorContent = document.querySelector("#editor-content");
const reauthDialog = document.querySelector("#reauth-dialog");
const reauthStatus = document.querySelector("#reauth-status");
const reauthConfirm = document.querySelector("#reauth-confirm");
const reauthCancel = document.querySelector("#reauth-cancel");
let state = null;
let settingsSaveChain = Promise.resolve();
let reauthPromise = null;
let resolveReauth = null;
let rejectReauth = null;

document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});
window.addEventListener("hashchange", showViewFromHash);
document.querySelector("#refresh-button").addEventListener("click", loadOverview);
document.querySelector("#user-search").addEventListener("input", renderUsers);
document.querySelector("#new-platform-button").addEventListener("click", openNewPlatform);
document.querySelector("#registration-settings").addEventListener("change", saveRegistration);
document.querySelector("#passkey-settings").addEventListener("change", handlePasskeySettingChange);
document.querySelectorAll("[data-clear-log]").forEach((button) => {
  button.addEventListener("click", () => clearLogs(button.dataset.clearLog));
});
reauthConfirm.addEventListener("click", verifyRecentPasskey);
reauthCancel.addEventListener("click", cancelRecentPasskey);
reauthDialog.addEventListener("cancel", (event) => {
  event.preventDefault();
  cancelRecentPasskey();
});

showViewFromHash();
loadOverview();

async function loadOverview() {
  try {
    state = await requestJson("/api/management/overview");
    renderAll();
    setStatus("数据已更新", "success", true);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

function renderAll() {
  renderUsers();
  renderPlatforms();
  renderLoginHistory();
  renderAuditLogs();
  renderSettings();
  renderPasskeySettings();
}

function showView(name, options = {}) {
  const target = [...document.querySelectorAll(".nav-item")]
    .find((item) => item.dataset.view === name);
  if (!target) {
    name = "users";
  }
  document.querySelectorAll(".nav-item").forEach((item) => {
    item.classList.toggle("is-active", item.dataset.view === name);
  });
  document.querySelectorAll(".view").forEach((view) => {
    view.classList.toggle("is-active", view.id === `${name}-view`);
  });
  const active = document.querySelector(`.nav-item[data-view="${name}"]`);
  document.querySelector("#view-title").textContent = active.textContent;
  if (options.updateHash !== false) {
    const nextHash = `#${name}`;
    if (window.location.hash !== nextHash) {
      window.history.pushState(null, "", nextHash);
    }
  }
}

function showViewFromHash() {
  const requestedView = window.location.hash.slice(1) || "users";
  const exists = [...document.querySelectorAll(".nav-item")]
    .some((item) => item.dataset.view === requestedView);
  showView(exists ? requestedView : "users", { updateHash: false });
  if (!exists && window.location.hash) {
    window.history.replaceState(null, "", "#users");
  }
}

function renderUsers() {
  if (!state) return;
  const query = document.querySelector("#user-search").value.trim().toLowerCase();
  const users = state.users.filter((user) =>
    `${user.username} ${user.sub}`.toLowerCase().includes(query),
  );
  renderList("#users-list", users, (user) => `
    <article class="data-row">
      <div class="row-primary">
        <strong>${escapeHtml(user.username)}</strong>
        <small>${escapeHtml(user.sub)}</small>
      </div>
      <span class="badge ${user.permissions.admin ? "is-on" : ""}">admin ${user.permissions.admin ? "on" : "off"}</span>
      <span class="badge ${user.permissions.login ? "is-on" : "is-off"}">login ${user.permissions.login ? "on" : "off"}</span>
      <span>${user.credentialCount} Passkey</span>
      <button data-edit-user="${user.id}">管理</button>
    </article>
  `);
  document.querySelectorAll("[data-edit-user]").forEach((button) => {
    button.addEventListener("click", () => openUser(Number(button.dataset.editUser)));
  });
}

function renderPlatforms() {
  if (!state) return;
  renderList("#platforms-list", state.platforms, (platform) => `
    <article class="data-row">
      <div class="row-primary">
        <strong>${escapeHtml(platform.name)}</strong>
        <small>${escapeHtml(platform.clientId)}</small>
      </div>
      <span class="badge ${platform.enabled ? "is-on" : "is-off"}">${platform.enabled ? "已启用" : "已停用"}</span>
      <span>${platform.redirectUris.length} 回调</span>
      <span>${platform.isDemo ? "内置 Demo" : "OAuth Client"}</span>
      <button data-edit-platform="${escapeHtml(platform.clientId)}">管理</button>
    </article>
  `);
  document.querySelectorAll("[data-edit-platform]").forEach((button) => {
    button.addEventListener("click", () => openPlatform(button.dataset.editPlatform));
  });
}

function renderLoginHistory() {
  if (!state) return;
  renderList("#login-history-list", state.loginHistory, (entry) => `
    <article class="data-row">
      <div class="row-primary">
        <strong>${escapeHtml(entry.username_snapshot || "未知用户")}</strong>
        <small>${formatTime(entry.created_at)}</small>
      </div>
      <span class="badge ${entry.result === "success" ? "is-on" : "is-off"}">${escapeHtml(entry.result)}</span>
      <span>${escapeHtml(entry.client_id || entry.flow)}</span>
      <span>${escapeHtml(entry.ip_address || "—")}</span>
      <button title="${escapeHtml(entry.user_agent || "")}">User-Agent</button>
    </article>
  `);
}

function renderAuditLogs() {
  if (!state) return;
  renderList("#audit-logs-list", state.auditLogs, (entry) => `
    <article class="data-row">
      <div class="row-primary">
        <strong>${escapeHtml(entry.action)}</strong>
        <small>${formatTime(entry.created_at)}</small>
      </div>
      <span>${escapeHtml(entry.actor_username || "已删除管理员")}</span>
      <span>${escapeHtml(entry.target_type || "—")}</span>
      <span>${escapeHtml(entry.target_id || "—")}</span>
      <button title="${escapeHtml(entry.details || "{}")}">详情</button>
    </article>
  `);
}

function renderSettings() {
  if (!state) return;
  const form = document.querySelector("#registration-settings");
  form.elements.mode.value = state.registration.mode;
  form.elements.defaultDemoAllowed.checked = state.registration.defaultDemoAllowed;
  form.elements.enabledUntil.value = state.registration.enabledUntil
    ? localDateTime(state.registration.enabledUntil)
    : "";
}

const algorithmPresets = {
  recommended: [-7, -8, -257],
  modern: [-7, -8],
  maximum: [-7, -8, -36, -37, -38, -39, -257, -258, -259],
};

function renderPasskeySettings() {
  if (!state) return;
  const form = document.querySelector("#passkey-settings");
  const settings = state.passkeySettings;
  form.elements.authenticatorAttachment.value = settings.authenticatorAttachment;
  form.elements.residentKey.value = settings.residentKey;
  form.elements.userVerification.value = settings.userVerification;
  form.elements.attestation.value = settings.attestation;
  form.elements.excludeCredentials.checked = settings.excludeCredentials;
  form.querySelectorAll('[name="algorithm"]').forEach((input) => {
    input.checked = settings.algorithms.includes(Number(input.value));
  });
  form.elements.hintPreset.value = hintPresetFor(settings.hints);
  syncAlgorithmPreset();
}

function applyAlgorithmPreset(value) {
  const algorithms = algorithmPresets[value];
  if (!algorithms) return;
  document.querySelectorAll('[name="algorithm"]').forEach((input) => {
    input.checked = algorithms.includes(Number(input.value));
  });
}

function syncAlgorithmPreset() {
  const selected = selectedAlgorithms();
  const preset = Object.entries(algorithmPresets).find(([, algorithms]) =>
    sameValues(selected, algorithms),
  );
  document.querySelector('[name="algorithmPreset"]').value = preset?.[0] || "custom";
}

function selectedAlgorithms() {
  return [...document.querySelectorAll('[name="algorithm"]:checked')]
    .map((input) => Number(input.value));
}

function hintPresetFor(hints) {
  if (sameValues(hints, ["client-device", "security-key", "hybrid"])) return "all";
  if (hints.length === 1) return hints[0];
  return "none";
}

function sameValues(left, right) {
  return left.length === right.length && left.every((value) => right.includes(value));
}

function openUser(userId) {
  const user = state.users.find((item) => item.id === userId);
  editorTitle.textContent = `管理 ${user.username}`;
  editorContent.innerHTML = `
    <section class="editor-section">
      <label>用户名<input id="edit-username" value="${escapeHtml(user.username)}"></label>
      <div class="permission-grid">
        ${permissionToggle("admin", user.permissions.admin)}
        ${permissionToggle("login", user.permissions.login)}
        ${permissionToggle("demo", user.permissions.demo)}
      </div>
      <label class="switch-row">
        <input id="edit-disabled" type="checkbox" ${user.disabledAt ? "checked" : ""}>
        <span>停用账户</span>
      </label>
    </section>
    <section class="editor-section">
      <h3>平台策略</h3>
      <label>模式
        <select id="policy-mode">
          <option value="allow_all">允许全部</option>
          <option value="allow_only">仅白名单</option>
          <option value="deny_only">黑名单排除</option>
        </select>
      </label>
      <div class="permission-grid">
        ${state.platforms.map((platform) => `
          <label class="switch-row">
            <input type="checkbox" data-policy-client="${escapeHtml(platform.clientId)}"
              ${user.platformPolicy.client_ids.includes(platform.clientId) ? "checked" : ""}>
            <span>${escapeHtml(platform.name)}</span>
          </label>
        `).join("")}
      </div>
    </section>
    <section class="editor-section">
      <h3>Passkey</h3>
      ${user.credentials.length ? user.credentials.map((credential) => `
        <div class="credential-card">
          <strong>${escapeHtml(credential.deviceType || "Passkey")}</strong>
          <p class="muted">${formatTime(credential.createdAt)} · ${credential.backedUp ? "已备份" : "未备份"}</p>
          <button type="button" class="danger-button" data-delete-credential="${credential.id}">删除 Passkey</button>
        </div>
      `).join("") : '<p class="muted">没有 Passkey</p>'}
    </section>
    <div class="editor-actions">
      <button type="button" class="primary-button" id="save-user">保存</button>
      <button type="button" id="revoke-user">撤销全部会话</button>
      <button type="button" class="danger-button" id="delete-user">删除用户</button>
    </div>
  `;
  document.querySelector("#policy-mode").value = user.platformPolicy.mode;
  document.querySelector("#save-user").addEventListener("click", () => saveUser(user));
  document.querySelector("#revoke-user").addEventListener("click", () => revokeSessions(user));
  document.querySelector("#delete-user").addEventListener("click", () => deleteUser(user));
  document.querySelectorAll("[data-delete-credential]").forEach((button) => {
    button.addEventListener("click", () => deleteCredential(user, Number(button.dataset.deleteCredential)));
  });
  dialog.showModal();
}

async function saveUser(user) {
  const platformClientIds = [...document.querySelectorAll("[data-policy-client]:checked")]
    .map((input) => input.dataset.policyClient);
  await mutate(`/api/management/users/${user.id}`, {
    method: "PATCH",
    body: {
      username: document.querySelector("#edit-username").value.trim(),
      disabled: document.querySelector("#edit-disabled").checked,
      permissions: {
        admin: document.querySelector("#permission-admin").checked,
        login: document.querySelector("#permission-login").checked,
        demo: document.querySelector("#permission-demo").checked,
      },
      platformPolicy: {
        mode: document.querySelector("#policy-mode").value,
        clientIds: platformClientIds,
      },
    },
  });
}

async function revokeSessions(user) {
  if (!confirm(`撤销 ${user.username} 的全部现有会话？`)) return;
  await mutate(`/api/management/users/${user.id}/revoke-sessions`, { method: "POST" });
}

async function deleteUser(user) {
  if (!confirm(`永久删除用户 ${user.username}？登录历史会保留为已删除用户快照。`)) return;
  await mutate(`/api/management/users/${user.id}`, { method: "DELETE" });
}

async function deleteCredential(user, credentialId) {
  if (!confirm(`删除 ${user.username} 的这个 Passkey？`)) return;
  await mutate(`/api/management/users/${user.id}/credentials/${credentialId}`, { method: "DELETE" });
}

function openNewPlatform() {
  editorTitle.textContent = "新建平台";
  editorContent.innerHTML = platformEditor();
  document.querySelector("#save-platform").addEventListener("click", async () => {
    const result = await requestJson("/api/management/platforms", {
      method: "POST",
      body: {
        name: document.querySelector("#platform-name").value.trim(),
        clientId: document.querySelector("#platform-client-id").value.trim(),
        redirectUris: document.querySelector("#platform-redirects").value,
      },
    });
    alert(`请立即保存 Client Secret，仅显示一次：\n\n${result.clientSecret}`);
    dialog.close();
    await loadOverview();
  });
  dialog.showModal();
}

function openPlatform(clientId) {
  const platform = state.platforms.find((item) => item.clientId === clientId);
  editorTitle.textContent = `管理 ${platform.name}`;
  editorContent.innerHTML = platformEditor(platform);
  document.querySelector("#save-platform").addEventListener("click", async () => {
    await mutate(`/api/management/platforms/${encodeURIComponent(clientId)}`, {
      method: "PATCH",
      body: {
        name: document.querySelector("#platform-name").value.trim(),
        redirectUris: document.querySelector("#platform-redirects").value,
        enabled: document.querySelector("#platform-enabled").checked,
      },
    });
  });
  document.querySelector("#rotate-platform").addEventListener("click", async () => {
    if (!confirm("轮换后旧 Client Secret 会立即失效。继续？")) return;
    const result = await requestJson(`/api/management/platforms/${encodeURIComponent(clientId)}/rotate-secret`, { method: "POST" });
    alert(`请立即保存新的 Client Secret，仅显示一次：\n\n${result.clientSecret}`);
    dialog.close();
    await loadOverview();
  });
  const deleteButton = document.querySelector("#delete-platform");
  if (deleteButton) {
    deleteButton.addEventListener("click", async () => {
      if (!confirm(`删除平台 ${platform.name}？`)) return;
      await mutate(`/api/management/platforms/${encodeURIComponent(clientId)}`, { method: "DELETE" });
    });
  }
  dialog.showModal();
}

function platformEditor(platform = null) {
  return `
    <section class="editor-section">
      <label>平台名称<input id="platform-name" value="${escapeHtml(platform?.name || "")}"></label>
      <label>Client ID<input id="platform-client-id" value="${escapeHtml(platform?.clientId || "")}" ${platform ? "disabled" : ""}></label>
      <label>回调地址<textarea id="platform-redirects">${escapeHtml((platform?.redirectUris || []).join("\n"))}</textarea></label>
      ${platform ? `<label class="switch-row"><input id="platform-enabled" type="checkbox" ${platform.enabled ? "checked" : ""}><span>启用平台</span></label>` : ""}
    </section>
    <div class="editor-actions">
      <button type="button" class="primary-button" id="save-platform">保存</button>
      ${platform ? '<button type="button" id="rotate-platform">轮换 Secret</button>' : ""}
      ${platform && !platform.isDemo ? '<button type="button" class="danger-button" id="delete-platform">删除平台</button>' : ""}
    </div>
  `;
}

function saveRegistration() {
  const form = document.querySelector("#registration-settings");
  const dateValue = form.elements.enabledUntil.value;
  if (form.elements.mode.value === "temporary" && !dateValue) {
    setStatus("请选择临时开放的结束时间", "error");
    form.elements.enabledUntil.focus();
    return;
  }
  const enabledUntil = dateValue
    ? Math.floor(new Date(dateValue).getTime() / 1000)
    : null;
  if (form.elements.mode.value === "temporary" && enabledUntil <= Math.floor(Date.now() / 1000)) {
    setStatus("临时开放时间必须晚于当前时间", "error");
    return;
  }
  queueSettingsSave("/api/management/settings/registration", {
    method: "PATCH",
    body: {
      mode: form.elements.mode.value,
      enabledUntil,
      defaultDemoAllowed: form.elements.defaultDemoAllowed.checked,
    },
  });
}

function handlePasskeySettingChange(event) {
  if (event.target.name === "algorithmPreset") {
    if (event.target.value === "custom") return;
    applyAlgorithmPreset(event.target.value);
  }
  if (event.target.name === "algorithm") {
    syncAlgorithmPreset();
  }
  savePasskeySettings();
}

function savePasskeySettings() {
  const form = document.querySelector("#passkey-settings");
  const algorithms = selectedAlgorithms();
  if (!algorithms.length) {
    setStatus("请至少启用一种公钥签名算法", "error");
    renderPasskeySettings();
    return;
  }
  const hintPreset = form.elements.hintPreset.value;
  const hints = hintPreset === "all"
    ? ["client-device", "security-key", "hybrid"]
    : hintPreset === "none" ? [] : [hintPreset];
  queueSettingsSave("/api/management/settings/passkey", {
    method: "PATCH",
    body: {
      algorithms,
      authenticatorAttachment: form.elements.authenticatorAttachment.value,
      residentKey: form.elements.residentKey.value,
      userVerification: form.elements.userVerification.value,
      attestation: form.elements.attestation.value,
      excludeCredentials: form.elements.excludeCredentials.checked,
      hints,
    },
  });
}

function queueSettingsSave(url, options) {
  settingsSaveChain = settingsSaveChain.then(async () => {
    setStatus("正在自动保存…", "muted");
    try {
      await requestJson(url, options);
      setStatus("已自动保存", "success", true);
    } catch (error) {
      setStatus(error.message, "error");
      try {
        state = await requestJson("/api/management/overview");
        renderAll();
      } catch (refreshError) {
        setStatus(refreshError.message, "error");
      }
    }
  });
}

async function clearLogs(logType) {
  try {
    const beforeInput = prompt("清理此时间之前的日志（ISO 日期）；留空表示全部清理。");
    if (beforeInput === null) return;
    const before = beforeInput.trim() ? Math.floor(new Date(beforeInput).getTime() / 1000) : null;
    if (beforeInput.trim() && !Number.isFinite(before)) {
      setStatus("日期格式无效", "error");
      return;
    }
    const query = before ? `?before=${before}` : "";
    const preview = await requestJson(`/api/management/logs/${logType}/count${query}`);
    if (!confirm(`将永久删除 ${preview.count} 条日志。确认清理？`)) return;
    await mutate(`/api/management/logs/${logType}/clear`, {
      method: "POST",
      body: { before },
    });
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function mutate(url, options) {
  try {
    await requestJson(url, options);
    dialog.close();
    await loadOverview();
    setStatus("更改已保存", "success", true);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function requestJson(url, options = {}) {
  const init = { method: options.method || "GET", headers: {} };
  if (init.method !== "GET") init.headers["X-CSRF-Token"] = csrfToken;
  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  const response = await fetch(url, init);
  const data = await response.json();
  if (response.status === 428 && !options.skipReauth) {
    await requireRecentPasskey();
    return requestJson(url, { ...options, skipReauth: true });
  }
  if (!response.ok) {
    const error = new Error(data.error || "请求失败");
    error.status = response.status;
    throw error;
  }
  return data;
}

function requireRecentPasskey() {
  if (reauthPromise) return reauthPromise;
  reauthStatus.hidden = true;
  reauthStatus.textContent = "";
  reauthConfirm.disabled = false;
  reauthDialog.showModal();
  reauthPromise = new Promise((resolve, reject) => {
    resolveReauth = resolve;
    rejectReauth = reject;
  });
  return reauthPromise;
}

async function verifyRecentPasskey() {
  reauthConfirm.disabled = true;
  setReauthStatus("等待浏览器 Passkey 操作…", "muted");
  try {
    if (!window.isSecureContext || !window.PublicKeyCredential) {
      throw new Error("请使用 HTTPS 或 localhost，并确认浏览器支持 Passkey");
    }
    const { publicKey } = await requestJson("/api/management/reauth/options", {
      method: "POST",
      skipReauth: true,
    });
    const assertion = await navigator.credentials.get({
      publicKey: decodeRequestOptions(publicKey),
    });
    await requestJson("/api/management/reauth/verify", {
      method: "POST",
      body: { credential: encodeAuthenticationCredential(assertion) },
      skipReauth: true,
    });
    reauthDialog.close();
    resolveReauth?.();
    clearReauthPromise();
    setStatus("身份验证完成，已继续操作", "success", true);
  } catch (error) {
    if (isPasskeyCancelError(error)) {
      setReauthStatus("Passkey 验证已取消", "muted");
    } else {
      setReauthStatus(error.message || String(error), "error");
    }
    reauthConfirm.disabled = false;
  }
}

function cancelRecentPasskey() {
  reauthDialog.close();
  rejectReauth?.(new Error("操作已取消，未进行任何更改"));
  clearReauthPromise();
}

function clearReauthPromise() {
  reauthPromise = null;
  resolveReauth = null;
  rejectReauth = null;
}

function setReauthStatus(message, kind) {
  reauthStatus.hidden = false;
  reauthStatus.textContent = message;
  reauthStatus.dataset.kind = kind;
}

function decodeRequestOptions(options) {
  return {
    ...options,
    challenge: base64urlToBuffer(options.challenge),
    allowCredentials: (options.allowCredentials || []).map((descriptor) => ({
      ...descriptor,
      id: base64urlToBuffer(descriptor.id),
    })),
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
  const bytes = Uint8Array.from(atob(padded), (character) => character.charCodeAt(0));
  return bytes.buffer;
}

function bufferToBase64url(buffer) {
  const binary = String.fromCharCode(...new Uint8Array(buffer));
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

function renderList(selector, items, renderer) {
  document.querySelector(selector).innerHTML = items.length
    ? items.map(renderer).join("")
    : '<p class="empty">暂无数据</p>';
}

function permissionToggle(key, checked) {
  return `<label class="switch-row">
    <input id="permission-${key}" type="checkbox" ${checked ? "checked" : ""}>
    <span>${key}</span>
  </label>`;
}

function formatTime(timestamp) {
  return timestamp ? new Date(timestamp * 1000).toLocaleString() : "—";
}

function localDateTime(timestamp) {
  const date = new Date(timestamp * 1000);
  const offset = date.getTimezoneOffset() * 60000;
  return new Date(date.getTime() - offset).toISOString().slice(0, 16);
}

function setStatus(message, kind, autoHide = false) {
  statusOutput.hidden = false;
  statusOutput.textContent = message;
  statusOutput.dataset.kind = kind;
  if (autoHide) setTimeout(() => { statusOutput.hidden = true; }, 4000);
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
