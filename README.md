# Passkey Auth Demo

一个使用 Python、Flask 和 `py_webauthn`（包名 `webauthn`）实现的 passkey 注册 / 登录 demo。

## 特性

- 用户可自定义用户名
- 支持注册、用户名登录和无用户名 passkey 登录
- 浏览器侧接口只返回最小登录状态，不把用户名放进 URL 或普通 UI 响应
- 提供服务端验证 API，方便作为自建 OAuth / SSO 的身份校验入口
- 内置 OAuth authorization code flow demo
- 内置第三方网页跳转和 OAuth 回跳 demo
- 内置 link challenge flow demo：模拟 `login.xxxxx` 跳转到 `auth.xxxxx/{challenge}`
- 使用标准 WebAuthn 浏览器接口：`navigator.credentials.create()` / `navigator.credentials.get()`
- 后端 passkey 逻辑位于可导入库函数中
- SQLite 本地存储用户和 credential public key
- 支持 Chrome、Safari、Firefox、Edge 等现代浏览器

## 高级文档与 Agent 入口

想了解完整 OAuth / SSO 接入、安全模型、生产部署、扩展方式或 Agent 友好的项目地图，请从 [项目 Wiki](https://github.com/jasonhejiahuan/Passkey-Auth/wiki) 开始。

推荐阅读路径：

- 开发者接入：先读 [Quick Start](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Quick-Start)，再读 [OAuth and SSO Integration](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/OAuth-and-SSO-Integration)
- 生产部署：读 [Configuration and Deployment](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Configuration-and-Deployment) 和 [Security Model](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Security-Model)
- AI coding agents / vibe coding：请优先读取 [Agents Vibe Coding Guide](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Agents-Vibe-Coding-Guide)，再根据任务查阅功能页；它包含项目地图、安全红线、推荐修改入口和测试策略

## 运行

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m passkey_demo.app
```

完整 OAuth 接入说明见：[OAuth 接入开发文档](docs/oauth-integration.md)。

然后打开：

```text
http://localhost:XXXX
```

如果本机 `XXXX` 端口被占用，可以换端口。WebAuthn 的 origin 必须和浏览器地址一致：

```bash
PORT=5001 PASSKEY_ORIGIN=http://localhost:5001 .venv/bin/python -m passkey_demo.app
```

未设置 `PASSKEY_ORIGIN` 时，demo 会自动使用当前请求地址，例如 `http://localhost:5002`。

Passkey / WebAuthn 要求安全上下文。`localhost` 属于浏览器允许的安全上下文；如果部署到线上，请使用 HTTPS，并把 `PASSKEY_RP_ID` 和 `PASSKEY_ORIGIN` 改成你的真实域名。

## 环境变量

默认配置集中在 `passkey_demo/config.py`，运行时仍可通过环境变量覆盖：

```bash
PASSKEY_RP_ID=localhost
PASSKEY_ORIGIN=http://localhost:5000
PASSKEY_RP_NAME="Passkey Demo"
PASSKEY_DATABASE=/path/to/passkeys.sqlite3
FLASK_SECRET_KEY=change-me
PASSKEY_REGISTRATION_ENABLED=false
PASSKEY_SERVER_API_TOKEN=change-this-server-token
PASSKEY_OAUTH_DEMO_CLIENT_ID=passkey-demo-client
PASSKEY_OAUTH_DEMO_CLIENT_SECRET=passkey-demo-secret
PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS=300
```

`PASSKEY_REGISTRATION_ENABLED` 默认关闭。需要创建新用户时再临时设置为 `true`、`1`、`yes` 或 `on`，避免机器人直接调用注册接口批量创建账号。

## 服务端验证 API

浏览器登录成功后，前端接口只返回：

```json
{"ok": true}
```

如需让你的业务后端确认用户身份，由业务后端调用：

```http
POST /api/server/session/verify
Authorization: Bearer $PASSKEY_SERVER_API_TOKEN
Content-Type: application/json
```

请求体可以省略，此时接口会验证当前请求携带的 Flask session cookie；也可以显式传入 cookie，便于服务端转发验证：

```json
{"sessionCookie": "session=..."}
```

验证成功时返回服务端可用的身份信息：

```json
{
  "ok": true,
  "authenticated": true,
  "user": {
    "sub": "stable-user-handle",
    "id": 1,
    "username": "laowang",
    "createdAt": 1780000000
  }
}
```

`sub` 来自 WebAuthn user handle，适合作为 OAuth / SSO 场景里的稳定用户标识。这个接口默认只有设置了 `PASSKEY_SERVER_API_TOKEN` 且 Bearer token 匹配时才会返回身份信息。

## OAuth Demo

启动后打开：

```text
http://localhost:5002/demo/oauth
```

流程：

1. Demo Client 页面跳转到 `/oauth/authorize`
2. Passkey-Auth 展示极简 Logo 页面，并自动呼出 passkey 验证
3. 登录成功后回调到 `/demo/oauth/callback?code=...&state=...`
4. Demo 后端使用 `client_id/client_secret/code/redirect_uri` 换取 token 和用户信息
5. 页面显示登录成功或失败

OAuth 相关端点：

```text
GET  /oauth/authorize
POST /oauth/authorize/complete
POST /oauth/token
GET  /oauth/userinfo
```

默认 demo client：

```text
client_id=passkey-demo-client
client_secret=passkey-demo-secret
redirect_uri=http://localhost:5002/demo/oauth/callback
```

如果你部署到其他域名或端口，设置 `PASSKEY_ORIGIN`，并可用 `PASSKEY_OAUTH_DEMO_REDIRECT_URI` 额外允许一个 callback 地址。OAuth callback URL 里只携带必要的 `code/state`，不会携带 `username`。

## 第三方网页跳转和跳回 Demo

启动后打开：

```text
http://localhost:5002/demo/third-party
```

流程：

1. 模拟第三方网页生成 `state`，跳转到 `/oauth/authorize`
2. Passkey-Auth 展示和根目录一致的极简 Logo 页面，并自动呼出 passkey 验证
3. 登录成功后跳回 `/demo/third-party/callback?code=...&state=...`
4. 第三方 callback 校验 `state`，用 `code` 调 `/oauth/token`
5. 第三方 callback 再用 `access_token` 调 `/oauth/userinfo`
6. 页面展示 callback 参数、token 响应和 userinfo 响应

这个页面会展示 `access_token`，只用于本地调试和理解 OAuth 回跳流程。生产环境不要把 access token 直接暴露在浏览器页面上。

## 链接跳转 Challenge Demo

启动后打开：

```text
http://localhost:5002/demo/link-login
```

这个 demo 模拟你描述的域名形态：

```text
https://login.xxxxx/                 原网站登录页
https://auth.xxxxx/oauth/challenge/{challenge}
https://login.xxxxx/callback         原网站回调页
```

本地流程：

1. 原网站页面输入用户名并提交到 `/demo/link-login/start`
2. 原网站后端创建一次性 `challenge`，保存 `username/state/return_uri/client_id`
3. 浏览器跳转到 `/oauth/challenge/{challenge}`
4. Auth WebUI 用该用户名发起 passkey 验证
5. 验证成功后，Auth 后端把 challenge 标记为完成，并签发 `challenge_result`
6. 浏览器跳回 `/demo/link-login/callback?challenge=...&challenge_result=...&state=...&status=success`
7. 原网站 callback 校验自己的 `state`，再服务端验证 `challenge_result` 签名和一次性 challenge 状态，校验成功后登录

注意：`status=success` 只是便于页面展示，不能作为登录依据。真正可信的是服务端校验后的 `challenge_result`，并且同一个 challenge 只能消费一次。

如果部署到两个真实子域名，WebAuthn 配置通常类似：

```bash
PASSKEY_RP_ID=xxxxx
PASSKEY_ORIGIN=https://auth.xxxxx
PASSKEY_OAUTH_DEMO_REDIRECT_URI=https://login.xxxxx/callback
```

`PASSKEY_RP_ID=xxxxx` 允许 `auth.xxxxx` 作为 passkey 的 RP 子域使用；浏览器实际打开 Auth WebUI 的 origin 必须和 `PASSKEY_ORIGIN` 一致。

## 可导入函数

核心函数在 `passkey_demo.webauthn_service`：

- `build_registration_options(...)`
- `verify_registration(...)`
- `build_authentication_options(...)`
- `verify_authentication(...)`

Flask demo 只是其中一种使用方式。
