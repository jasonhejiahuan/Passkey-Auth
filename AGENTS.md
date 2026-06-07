# AGENTS.md

This repository welcomes agentic coding work. Optimize for small, correct, well-tested changes that preserve the passkey-first user experience.

本仓库欢迎 Agentic Coding 工作流。请优先做小而正确、可验证的改动，并保持 passkey 优先的用户体验。

## Start Here

Read the project Wiki before making broad changes:

在进行较大改动前，请先阅读项目 Wiki：

- Project overview: https://github.com/jasonhejiahuan/Passkey-Auth/wiki
- Agent guide: https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Agents-Vibe-Coding-Guide
- OAuth integration: https://github.com/jasonhejiahuan/Passkey-Auth/wiki/OAuth-and-SSO-Integration
- Security model: https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Security-Model

## Project Map

- `passkey_demo/app.py`: Flask routes, OAuth flow, link challenge flow, session verify API. / Flask 路由、OAuth 流程、link challenge 流程、session verify API。
- `passkey_demo/config.py`: default config values and environment overrides. / 默认配置和环境变量覆盖。
- `passkey_demo/storage.py`: SQLite users, credentials, OAuth codes, challenge requests. / SQLite 用户、凭据、OAuth code、challenge 存储。
- `passkey_demo/webauthn_service.py`: WebAuthn option generation and verification. / WebAuthn options 生成与验证。
- `passkey_demo/static/`: browser passkey flows and UI behavior. / 浏览器 passkey 流程和 UI 行为。
- `passkey_demo/templates/`: minimal Auth WebUI and demo pages. / 极简 Auth WebUI 和 demo 页面。
- `tests/`: config, registration gate, OAuth, and challenge flow tests. / 配置、注册保护、OAuth 和 challenge 测试。

## Safety Invariants

Keep these true:

请保持以下不变量成立：

- WebAuthn challenges are generated server-side and verified server-side. / WebAuthn challenge 必须由服务端生成并由服务端验证。
- OAuth `state` is required and must be checked before token exchange. / OAuth `state` 必须存在，并且必须在换 token 前校验。
- Authorization codes are single-use and bound to `client_id` plus `redirect_uri`. / Authorization code 必须一次性使用，并绑定 `client_id` 与 `redirect_uri`。
- Link challenges are single-use; `status=success` is display-only, never auth proof. / Link challenge 必须一次性使用；`status=success` 只用于展示，不能作为登录凭据。
- `client_secret`, server API tokens, session cookies, access tokens, and raw credentials must not be exposed in browser UI or committed. / 不要在浏览器 UI 或提交中暴露 `client_secret`、server API token、session cookie、access token 或原始凭据。
- Registration stays disabled by default. / 注册默认保持关闭。
- `PASSKEY_ORIGIN` must match the browser origin used for WebAuthn. / `PASSKEY_ORIGIN` 必须匹配浏览器实际用于 WebAuthn 的 origin。

## Development Loop

Use the local virtualenv:

使用本地虚拟环境运行测试：

```bash
.venv/bin/python -m unittest discover -s tests -v
```

For local browser testing:

本地浏览器验证：

```bash
PORT=5003 PASSKEY_ORIGIN=http://localhost:5003 .venv/bin/python -m passkey_demo.app
```

If you touch UI, check desktop and mobile layouts. If you touch auth, OAuth, storage, or config, add or update tests.

如果改动 UI，请检查桌面端和移动端布局。如果改动认证、OAuth、存储或配置，请新增或更新测试。

## Change Style

- Prefer focused patches over broad rewrites. / 优先做聚焦补丁，避免大范围重写。
- Follow existing Flask, SQLite, and plain JavaScript patterns. / 遵循现有 Flask、SQLite 和原生 JavaScript 风格。
- Keep the UI quiet, modern, and user-first. / 保持 UI 安静、现代、用户优先。
- Keep documentation in sync with behavior. / 行为变化时同步更新文档。
- Do not commit `.env`, SQLite databases, `.venv`, `.DS_Store`, generated caches, or real secrets. / 不要提交 `.env`、SQLite 数据库、`.venv`、`.DS_Store`、生成缓存或真实密钥。
