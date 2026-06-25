"use strict";

const ACTION_TOKEN_STORAGE_KEY = "passkey-action-token";
const csrfToken = document.querySelector('meta[name="management-csrf-token"]').content;
const statusOutput = document.querySelector("#management-status");
const dialog = document.querySelector("#editor-dialog");
const editorTitle = document.querySelector("#editor-title");
const editorContent = document.querySelector("#editor-content");
let actionToken = window.sessionStorage.getItem(ACTION_TOKEN_STORAGE_KEY) || "";
let state = null;
let telemetryState = null;
let telemetryLoaded = false;
let settingsSaveChain = Promise.resolve();
let statusTimer = null;

document.querySelectorAll(".nav-item").forEach((button) => {
  button.addEventListener("click", () => showView(button.dataset.view));
});
window.addEventListener("hashchange", showViewFromHash);
document.querySelector("#refresh-button").addEventListener("click", loadOverview);
document.querySelector("#logout-button").addEventListener("click", logout);
document.querySelector("#user-search").addEventListener("input", renderUsers);
document.querySelector("#new-platform-button").addEventListener("click", openNewPlatform);
document.querySelector("#registration-settings").addEventListener("change", saveRegistration);
document.querySelector("#passkey-settings").addEventListener("change", handlePasskeySettingChange);
document.querySelector("#telemetry-settings").addEventListener("change", saveTelemetrySettings);
document.querySelector("#telemetry-backend-settings").addEventListener("submit", saveTelemetryBackend);
document.querySelector("#telemetry-backend-settings").addEventListener("change", renderTelemetryBackendFields);
document.querySelector("#test-telemetry-backend").addEventListener("click", testTelemetryBackend);
document.querySelector("#pair-jason-telemetry").addEventListener("click", pairJasonTelemetry);
document.querySelector("#clear-telemetry-button").addEventListener("click", clearTelemetry);
document.querySelectorAll("[data-clear-log]").forEach((button) => {
  button.addEventListener("click", () => clearLogs(button.dataset.clearLog));
});
showViewFromHash();
loadOverview();

async function loadOverview() {
  try {
    state = await requestJson("/api/management/overview");
    renderAll();
    if (telemetryLoaded) await loadTelemetry({ silent: true });
    setStatus("数据已更新", "success", true);
  } catch (error) {
    setStatus(error.message, "error");
  }
}

async function logout() {
  const button = document.querySelector("#logout-button");
  button.disabled = true;
  button.textContent = "正在退出…";
  try {
    await requestJson("/api/logout", { method: "POST" });
    window.sessionStorage.removeItem(ACTION_TOKEN_STORAGE_KEY);
    window.location.replace("/");
  } catch (error) {
    button.disabled = false;
    button.textContent = "退出登录";
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
  if (name === "telemetry") void loadTelemetry();
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
      <span>${platform.isDemo ? "内置示例" : "OAuth Client"}</span>
      <button data-edit-platform="${escapeHtml(platform.clientId)}">管理</button>
    </article>
  `);
  document.querySelectorAll("[data-edit-platform]").forEach((button) => {
    button.addEventListener("click", () => openPlatform(button.dataset.editPlatform));
  });
}

function renderLoginHistory() {
  if (!state) return;
  renderList("#login-history-list", state.loginHistory, (entry, index) => `
    <article class="data-row">
      <div class="row-primary">
        <strong>${escapeHtml(entry.username_snapshot || "未知用户")}</strong>
        <small>${formatTime(entry.created_at)}</small>
      </div>
      <span class="badge ${entry.result === "success" ? "is-on" : "is-off"}">${escapeHtml(entry.result)}</span>
      <span>${escapeHtml(entry.client_id || entry.flow)}</span>
      <span>${escapeHtml(entry.ip_address || "—")}</span>
      <button type="button" data-user-agent="${index}">User-Agent</button>
    </article>
  `);
  document.querySelectorAll("[data-user-agent]").forEach((button) => {
    button.addEventListener("click", () => {
      const entry = state.loginHistory[Number(button.dataset.userAgent)];
      openDetail("User-Agent", entry.user_agent || "未记录 User-Agent");
    });
  });
}

function renderAuditLogs() {
  if (!state) return;
  renderList("#audit-logs-list", state.auditLogs, (entry, index) => `
    <article class="data-row">
      <div class="row-primary">
        <strong>${escapeHtml(entry.action)}</strong>
        <small>${formatTime(entry.created_at)}</small>
      </div>
      <span>${escapeHtml(entry.actor_username || "已删除管理员")}</span>
      <span>${escapeHtml(entry.target_type || "—")}</span>
      <span>${escapeHtml(entry.target_id || "—")}</span>
      <button type="button" data-audit-detail="${index}">详情</button>
    </article>
  `);
  document.querySelectorAll("[data-audit-detail]").forEach((button) => {
    button.addEventListener("click", () => {
      const entry = state.auditLogs[Number(button.dataset.auditDetail)];
      openDetail("审计详情", entry.details || "{}");
    });
  });
}

function openDetail(title, value) {
  editorTitle.textContent = title;
  editorContent.innerHTML = `
    <section class="editor-section detail-section">
      <pre>${escapeHtml(value)}</pre>
    </section>
  `;
  dialog.showModal();
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
      <label class="toggle-row">
        <input id="edit-disabled" type="checkbox" ${user.disabledAt ? "checked" : ""}>
        <span class="toggle-control" aria-hidden="true"></span>
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
      ${platform ? `<label class="toggle-row"><input id="platform-enabled" type="checkbox" ${platform.enabled ? "checked" : ""}><span class="toggle-control" aria-hidden="true"></span><span>启用平台</span></label>` : ""}
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

const telemetryFeatureLabels = {
  screen: "屏幕",
  hardware: "硬件",
  fonts: "字体",
  battery: "电池",
  network: "网络",
  preferences: "显示偏好",
};

async function loadTelemetry(options = {}) {
  if (!options.silent) {
    document.querySelector("#telemetry-summary").innerHTML =
      '<p class="empty compact-empty">正在读取遥测统计…</p>';
  }
  try {
    telemetryState = await requestJson("/api/management/telemetry");
    telemetryLoaded = true;
    renderTelemetry();
  } catch (error) {
    setStatus(error.message, "error");
  }
}

function renderTelemetry() {
  if (!telemetryState || !state) return;
  const form = document.querySelector("#telemetry-settings");
  const settings = telemetryState.settings;
  form.elements.enabled.checked = settings.enabled;
  form.elements.anonymousEnabled.checked = settings.anonymousEnabled;
  form.elements.retentionDays.value = String(settings.retentionDays);
  form.querySelectorAll('[name="telemetryFeature"]').forEach((input) => {
    input.checked = settings.defaultFeatures.includes(input.value);
  });
  renderTelemetryBackend();
  const external = settings.backend !== "builtin";
  document.querySelector("#telemetry-local-actions").hidden = external;
  const notice = document.querySelector("#telemetry-external-notice");
  notice.hidden = !external;
  if (external) {
    const backendLabel = settings.backend === "jason"
      ? "jason-telemetry"
      : "自定义第三方服务";
    const pathLabel = settings.deliveryMode === "direct"
      ? "浏览器直接发送，Passkey-Auth 不接收或保存样本"
      : "由 Passkey-Auth 的有界后台队列异步转发";
    notice.textContent = `当前数据由 ${backendLabel} 保存；${pathLabel}。本地统计、CSV 和清理功能不会触发外部查询。`;
  }
  renderTelemetrySummary();
  if (external) {
    ["#telemetry-os-chart", "#telemetry-browser-chart", "#telemetry-device-chart", "#telemetry-feature-chart"]
      .forEach((selector) => {
        document.querySelector(selector).innerHTML =
          '<p class="muted chart-empty">统计由外部接收端管理</p>';
      });
  } else {
    renderTelemetryChart(
      "#telemetry-os-chart",
      telemetryState.statistics.distributions.operatingSystems,
    );
    renderTelemetryChart(
      "#telemetry-browser-chart",
      telemetryState.statistics.distributions.browsers,
    );
    renderTelemetryChart(
      "#telemetry-device-chart",
      telemetryState.statistics.distributions.devices,
    );
    renderTelemetryChart(
      "#telemetry-feature-chart",
      telemetryState.statistics.distributions.features,
    );
  }
  renderTelemetryEvents();
  renderTelemetryUsers();
}

function renderTelemetrySummary() {
  if (telemetryState.settings.backend !== "builtin") {
    const delivery = telemetryState.settings.delivery;
    const direct = telemetryState.settings.deliveryMode === "direct";
    const metrics = direct
      ? [
        ["发送路径", "浏览器直连"],
        ["服务端队列", "未启动"],
        ["本地落盘", "关闭"],
        ["密钥下发", "不会"],
      ]
      : [
        ["等待发送", delivery.queued.toLocaleString()],
        ["已发送", delivery.sent.toLocaleString()],
        ["失败", delivery.failed.toLocaleString()],
        ["队列丢弃", delivery.dropped.toLocaleString()],
      ];
    document.querySelector("#telemetry-summary").innerHTML = metrics.map(([label, value]) => `
      <article class="metric-card">
        <span>${label}</span>
        <strong>${value}</strong>
      </article>
    `).join("");
    return;
  }
  const summary = telemetryState.statistics.summary;
  const metrics = [
    ["总样本", summary.total.toLocaleString()],
    ["24 小时", summary.last24h.toLocaleString()],
    ["已识别用户", summary.identifiedUsers.toLocaleString()],
    ["平均载荷", `${summary.averagePayloadBytes.toLocaleString()} B`],
  ];
  document.querySelector("#telemetry-summary").innerHTML = metrics.map(([label, value]) => `
    <article class="metric-card">
      <span>${label}</span>
      <strong>${value}</strong>
    </article>
  `).join("");
}

function renderTelemetryChart(selector, items) {
  const target = document.querySelector(selector);
  if (!items.length) {
    target.innerHTML = '<p class="muted chart-empty">暂无数据</p>';
    return;
  }
  const maximum = Math.max(...items.map((item) => item.count), 1);
  target.innerHTML = items.slice(0, 8).map((item) => {
    const width = Math.max(Math.round((item.count / maximum) * 100), 4);
    const widthClass = Math.min(Math.max(Math.ceil(width / 10) * 10, 10), 100);
    const label = telemetryFeatureLabels[item.label] || item.label;
    return `
      <div class="bar-row">
        <div><span>${escapeHtml(label)}</span><strong>${item.count}</strong></div>
        <span class="bar-track"><span class="bar-fill bar-width-${widthClass}"></span></span>
      </div>
    `;
  }).join("");
}

function renderTelemetryEvents() {
  if (telemetryState.settings.backend !== "builtin") {
    document.querySelector("#telemetry-recent-list").innerHTML =
      '<p class="empty">外部模式不会在 Passkey-Auth 中保留样本。</p>';
    return;
  }
  const entries = telemetryState.statistics.recent;
  renderList("#telemetry-recent-list", entries, (entry, index) => {
    const user = entry.userId
      ? state.users.find((candidate) => candidate.id === entry.userId)
      : null;
    const featureNames = entry.features
      .map((feature) => telemetryFeatureLabels[feature] || feature)
      .join("、");
    return `
      <article class="data-row telemetry-event-row">
        <div class="row-primary">
          <strong>${escapeHtml(user?.username || (entry.userId ? `已删除用户 #${entry.userId}` : "匿名访客"))}</strong>
          <small>${formatTime(entry.createdAt)} · ${escapeHtml(entry.path)}</small>
        </div>
        <span>${escapeHtml(entry.osFamily)} / ${escapeHtml(entry.browserFamily)}</span>
        <span>${escapeHtml(entry.deviceClass)}</span>
        <span>${escapeHtml(featureNames)}</span>
        <button type="button" data-telemetry-detail="${index}">详情</button>
      </article>
    `;
  });
  document.querySelectorAll("[data-telemetry-detail]").forEach((button) => {
    button.addEventListener("click", () => {
      const entry = telemetryState.statistics.recent[Number(button.dataset.telemetryDetail)];
      openDetail("遥测样本", JSON.stringify(entry, null, 2));
    });
  });
}

function renderTelemetryUsers() {
  const policies = telemetryState.userPolicies;
  document.querySelector("#telemetry-users-list").innerHTML = state.users.map((user) => {
    const policy = policies[String(user.id)] || { mode: "inherit", features: [] };
    const effectiveFeatures = policy.mode === "inherit"
      ? telemetryState.settings.defaultFeatures
      : policy.features;
    return `
      <article class="telemetry-policy-row" data-telemetry-user="${user.id}">
        <div class="row-primary">
          <strong>${escapeHtml(user.username)}</strong>
          <small>${policy.mode === "off" ? "不下发任何遥测代码" : policy.mode === "custom" ? "仅下发自定义模块" : "继承默认策略"}</small>
        </div>
        <label>策略
          <select data-telemetry-user-mode="${user.id}">
            <option value="inherit" ${policy.mode === "inherit" ? "selected" : ""}>继承默认</option>
            <option value="off" ${policy.mode === "off" ? "selected" : ""}>关闭</option>
            <option value="custom" ${policy.mode === "custom" ? "selected" : ""}>自定义</option>
          </select>
        </label>
        <div class="telemetry-user-features">
          ${Object.entries(telemetryFeatureLabels).map(([feature, label]) => `
            <label class="switch-row">
              <input type="checkbox" data-telemetry-user-feature="${user.id}" value="${feature}"
                ${effectiveFeatures.includes(feature) ? "checked" : ""}
                ${policy.mode !== "custom" ? "disabled" : ""}>
              <span>${label}</span>
            </label>
          `).join("")}
        </div>
      </article>
    `;
  }).join("") || '<p class="empty">暂无用户</p>';

  document.querySelectorAll("[data-telemetry-user-mode]").forEach((select) => {
    select.addEventListener("change", () => {
      const userId = Number(select.dataset.telemetryUserMode);
      const row = document.querySelector(`[data-telemetry-user="${userId}"]`);
      row.querySelectorAll("[data-telemetry-user-feature]").forEach((input) => {
        input.disabled = select.value !== "custom";
        if (select.value === "custom" && !input.checked) {
          input.checked = telemetryState.settings.defaultFeatures.includes(input.value);
        }
      });
      saveUserTelemetry(userId);
    });
  });
  document.querySelectorAll("[data-telemetry-user-feature]").forEach((input) => {
    input.addEventListener("change", () => {
      saveUserTelemetry(Number(input.dataset.telemetryUserFeature));
    });
  });
}

function renderTelemetryBackend() {
  const form = document.querySelector("#telemetry-backend-settings");
  const settings = telemetryState.settings;
  form.elements.backend.value = settings.backend;
  form.elements.deliveryMode.value = settings.deliveryMode;
  form.elements.jasonBaseUrl.value = settings.jason.baseUrl || "";
  form.elements.jasonApiKey.value = "";
  form.elements.jasonApiKey.placeholder = settings.jason.apiKeyConfigured
    ? "已配置；留空表示保持当前密钥"
    : "输入 jason-telemetry API Key";
  form.elements.clearJasonApiKey.checked = false;
  form.elements.customUrl.value = settings.custom.url || "";
  form.elements.customAuthMode.value = settings.custom.authMode;
  form.elements.customAuthHeader.value = settings.custom.authHeader || "X-Api-Key";
  form.elements.customSecret.value = "";
  form.elements.customSecret.placeholder = settings.custom.secretConfigured
    ? "已配置；留空表示保持当前密钥"
    : "输入认证密钥";
  form.elements.clearCustomSecret.checked = false;
  form.elements.customHeaders.value = JSON.stringify(settings.custom.headers || {}, null, 2);
  form.elements.customDirectContentType.value = settings.custom.directContentType;
  form.elements.timeoutSeconds.value = String(settings.timeoutSeconds);
  renderTelemetryBackendFields();
  renderTelemetryDeliveryStatus();
}

function renderTelemetryBackendFields() {
  const form = document.querySelector("#telemetry-backend-settings");
  const backend = form.elements.backend.value;
  const delivery = form.elements.deliveryMode;
  if (backend === "builtin") {
    delivery.value = "relay";
    delivery.disabled = true;
  } else {
    delivery.disabled = false;
  }
  const deliveryMode = delivery.value;
  document.querySelector("#telemetry-jason-fields").hidden = backend !== "jason";
  document.querySelector("#telemetry-custom-fields").hidden = backend !== "custom";
  document.querySelector("#telemetry-direct-content-type").hidden =
    backend !== "custom" || deliveryMode !== "direct";

  const authMode = form.elements.customAuthMode.value;
  document.querySelector("#telemetry-custom-auth-header").hidden = authMode !== "header";
  document.querySelector("#telemetry-custom-secret").hidden = authMode === "none";
  document.querySelector("#telemetry-clear-custom-secret").hidden = authMode === "none";

  const note = document.querySelector("#telemetry-delivery-note");
  if (backend === "builtin") {
    note.textContent = "样本由内置 SQLite 保存并驱动本页统计。不会加载任何外部适配器。";
  } else if (deliveryMode === "direct") {
    note.textContent = "浏览器取得临时目标后直接发送，节省 Passkey-Auth 带宽和 CPU；目标必须支持浏览器跨域或免预检文本 POST。";
  } else {
    note.textContent = "浏览器只连接 Passkey-Auth；服务端验证样本后立即入有界队列，由后台线程转发，不等待外部服务响应。";
  }
}

function renderTelemetryDeliveryStatus() {
  const settings = telemetryState.settings;
  const target = document.querySelector("#telemetry-delivery-status");
  if (settings.backend === "builtin") {
    target.textContent = "当前使用内置事件库。";
    return;
  }
  if (settings.deliveryMode === "direct") {
    target.textContent = "浏览器直连模式不在 Passkey-Auth 中维护外部发送计数。";
    return;
  }
  const delivery = settings.delivery;
  target.textContent = delivery.state === "idle"
    ? "后台发送器尚未启动；第一条有效样本到达时才会按需加载。"
    : `后台队列 ${delivery.queued}，成功 ${delivery.sent}，失败 ${delivery.failed}，丢弃 ${delivery.dropped}。`;
}

function saveTelemetrySettings() {
  const form = document.querySelector("#telemetry-settings");
  const defaultFeatures = [...form.querySelectorAll('[name="telemetryFeature"]:checked')]
    .map((input) => input.value);
  if (form.elements.enabled.checked && !defaultFeatures.length) {
    setStatus("启用遥测时至少选择一种采集能力", "error");
    renderTelemetry();
    return;
  }
  queueTelemetrySave("/api/management/settings/telemetry", {
    method: "PATCH",
    body: {
      enabled: form.elements.enabled.checked,
      anonymousEnabled: form.elements.anonymousEnabled.checked,
      defaultFeatures,
      retentionDays: Number(form.elements.retentionDays.value),
    },
  });
}

async function saveTelemetryBackend(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const backend = form.elements.backend.value;
  const deliveryMode = backend === "builtin"
    ? "relay"
    : form.elements.deliveryMode.value;
  let customHeaders;
  try {
    customHeaders = JSON.parse(form.elements.customHeaders.value || "{}");
    if (!customHeaders || Array.isArray(customHeaders) || typeof customHeaders !== "object") {
      throw new Error();
    }
  } catch (_error) {
    setStatus("非敏感 Headers 必须是 JSON 对象", "error");
    return;
  }
  if (
    backend === "custom"
    && deliveryMode === "direct"
    && form.elements.customAuthMode.value !== "none"
  ) {
    setStatus("浏览器直连不能使用服务端保存的私有认证密钥", "error");
    return;
  }

  const baseForm = document.querySelector("#telemetry-settings");
  const defaultFeatures = [...baseForm.querySelectorAll('[name="telemetryFeature"]:checked')]
    .map((input) => input.value);
  const body = {
    enabled: baseForm.elements.enabled.checked,
    anonymousEnabled: baseForm.elements.anonymousEnabled.checked,
    defaultFeatures,
    retentionDays: Number(baseForm.elements.retentionDays.value),
    backend,
    deliveryMode,
    jasonBaseUrl: form.elements.jasonBaseUrl.value.trim(),
    customUrl: form.elements.customUrl.value.trim(),
    customAuthMode: form.elements.customAuthMode.value,
    customAuthHeader: form.elements.customAuthHeader.value.trim(),
    customHeaders,
    customDirectContentType: form.elements.customDirectContentType.value,
    timeoutSeconds: Number(form.elements.timeoutSeconds.value),
    clearJasonApiKey: form.elements.clearJasonApiKey.checked,
    clearCustomSecret: form.elements.clearCustomSecret.checked,
  };
  if (form.elements.jasonApiKey.value) body.jasonApiKey = form.elements.jasonApiKey.value;
  if (form.elements.customSecret.value) body.customSecret = form.elements.customSecret.value;
  setStatus("正在保存后端配置…", "muted");
  try {
    await requestJson("/api/management/settings/telemetry", {
      method: "PATCH",
      body,
    });
    await loadTelemetry({ silent: true });
    setStatus("后端配置已保存", "success", true);
  } catch (error) {
    setStatus(error.message, "error");
    await loadTelemetry({ silent: true });
  }
}

async function testTelemetryBackend() {
  const button = document.querySelector("#test-telemetry-backend");
  button.disabled = true;
  try {
    const result = await requestJson("/api/management/telemetry/backend/test", {
      method: "POST",
      body: {},
    });
    const latency = result.latencyMs === undefined ? "" : `，${result.latencyMs} ms`;
    setStatus(`遥测后端连接成功${latency}`, "success", true);
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

async function pairJasonTelemetry() {
  const form = document.querySelector("#telemetry-backend-settings");
  const baseUrl = form.elements.jasonBaseUrl.value.trim();
  const pairingCode = form.elements.jasonPairingCode.value.trim();
  if (!baseUrl || !pairingCode) {
    setStatus("请输入 jason-telemetry 地址和一次性配对码", "error");
    return;
  }
  const button = document.querySelector("#pair-jason-telemetry");
  button.disabled = true;
  setStatus("正在与 jason-telemetry 安全协商…", "muted");
  try {
    const result = await requestJson(
      "/api/management/telemetry/backend/pair-jason",
      {
        method: "POST",
        body: {
          baseUrl,
          pairingCode,
          timeoutSeconds: Number(form.elements.timeoutSeconds.value),
          deliveryMode: form.elements.deliveryMode.value,
        },
      },
    );
    form.elements.jasonPairingCode.value = "";
    await loadTelemetry({ silent: true });
    const version = result.serverVersion ? `（${result.serverVersion}）` : "";
    setStatus(`自动配对成功${version}，API Key 已保存且不会回显`, "success", true);
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    button.disabled = false;
  }
}

function saveUserTelemetry(userId) {
  const row = document.querySelector(`[data-telemetry-user="${userId}"]`);
  const mode = row.querySelector("[data-telemetry-user-mode]").value;
  const features = [...row.querySelectorAll("[data-telemetry-user-feature]:checked")]
    .map((input) => input.value);
  if (mode === "custom" && !features.length) {
    setStatus("自定义用户策略至少选择一种采集能力", "error");
    renderTelemetryUsers();
    return;
  }
  queueTelemetrySave(`/api/management/users/${userId}/telemetry`, {
    method: "PATCH",
    body: { mode, features },
  });
}

function queueTelemetrySave(url, options) {
  settingsSaveChain = settingsSaveChain.then(async () => {
    setStatus("正在自动保存…", "muted");
    try {
      await requestJson(url, options);
      await loadTelemetry({ silent: true });
      setStatus("已自动保存", "success", true);
    } catch (error) {
      setStatus(error.message, "error");
      await loadTelemetry({ silent: true });
    }
  });
}

async function clearTelemetry() {
  try {
    const beforeInput = prompt("清理此时间之前的遥测数据（ISO 日期）；留空表示全部清理。");
    if (beforeInput === null) return;
    const before = beforeInput.trim()
      ? Math.floor(new Date(beforeInput).getTime() / 1000)
      : null;
    if (beforeInput.trim() && !Number.isFinite(before)) {
      setStatus("日期格式无效", "error");
      return;
    }
    const query = before ? `?before=${before}` : "";
    const preview = await requestJson(`/api/management/telemetry/events/count${query}`);
    if (!confirm(`将永久删除 ${preview.count} 条遥测样本。确认清理？`)) return;
    await requestJson("/api/management/telemetry/events/clear", {
      method: "POST",
      body: { before },
    });
    await loadTelemetry({ silent: true });
    setStatus(`已清理 ${preview.count} 条遥测样本`, "success", true);
  } catch (error) {
    setStatus(error.message, "error");
  }
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
  if (
    init.method !== "GET" &&
    url.startsWith("/api/management/") &&
    actionToken
  ) {
    init.headers["X-Action-Token"] = actionToken;
  }
  if (options.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(options.body);
  }
  const response = await fetch(url, init);
  const data = await response.json();
  if (response.ok && data.next_action_token) {
    actionToken = data.next_action_token;
    window.sessionStorage.setItem(ACTION_TOKEN_STORAGE_KEY, actionToken);
  }
  if ((response.status === 428 || data.reauth_required) && !options.skipReauth) {
    if (data.reauth_required) {
      actionToken = "";
      window.sessionStorage.removeItem(ACTION_TOKEN_STORAGE_KEY);
    }
    const returnTo = `${window.location.pathname}${window.location.search}${window.location.hash}`;
    const query = new URLSearchParams({ mode: "reauth", return_to: returnTo });
    window.location.assign(`/auth/passkey?${query}`);
    throw new Error("正在前往标准 Passkey 验证页面");
  }
  if (!response.ok) {
    const error = new Error(data.error || "请求失败");
    error.status = response.status;
    throw error;
  }
  return data;
}

function renderList(selector, items, renderer) {
  document.querySelector(selector).innerHTML = items.length
    ? items.map(renderer).join("")
    : '<p class="empty">暂无数据</p>';
}

function permissionToggle(key, checked) {
  return `<label class="toggle-row">
    <input id="permission-${key}" type="checkbox" ${checked ? "checked" : ""}>
    <span class="toggle-control" aria-hidden="true"></span>
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
  if (statusTimer) window.clearTimeout(statusTimer);
  statusOutput.hidden = false;
  statusOutput.textContent = message;
  statusOutput.dataset.kind = kind;
  if (autoHide) {
    statusTimer = window.setTimeout(() => {
      statusOutput.hidden = true;
      statusTimer = null;
    }, 10000);
  }
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}
