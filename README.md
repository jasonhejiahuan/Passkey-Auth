此项目正在重构，在此过程中更新比较快～

# Passkey Auth

一个使用 Python、Flask 和 `py_webauthn`（包名 `webauthn`）实现的 passkey 注册、登录、OAuth / SSO 认证服务。

## 特性

- 用户可自定义用户名
- 支持注册、用户名登录和无用户名 passkey 登录
- 浏览器侧接口只返回最小登录状态，不把用户名放进 URL 或普通 UI 响应
- 提供服务端验证 API，方便作为自建 OAuth / SSO 的身份校验入口
- 内置 OAuth authorization code flow
- 内置第三方网页跳转和 OAuth 回跳示例，复用标准 OAuth client 管道
- 内置 link challenge flow 示例：模拟 `login.xxxxx` 跳转到 `auth.xxxxx/{challenge}`
- 使用标准 WebAuthn 浏览器接口：`navigator.credentials.create()` / `navigator.credentials.get()`
- 后端 passkey 逻辑位于可导入库函数中
- SQLite 本地存储用户和 credential public key
- 支持 Chrome、Safari、Firefox、Edge 等现代浏览器

## AI 协作声明

本项目由仓库所有者与 OpenAI Codex 协作开发。该声明由仓库所有者主动保留，用于透明记录 AI-assisted development；项目授权、免责声明和责任限制以 Apache License 2.0 为准。贡献范围见 [AI_ATTRIBUTION.md](AI_ATTRIBUTION.md)。

## 高级文档与 Agent 入口

想了解完整 OAuth / SSO 接入、安全模型、生产部署、扩展方式或 Agent 友好的项目地图，请从 [项目 Wiki](https://github.com/jasonhejiahuan/Passkey-Auth/wiki) 开始。

推荐阅读路径：

- 开发者接入：先读 [Quick Start](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Quick-Start)，再读 [Authentication Flows](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Authentication-Flows)
- 生产部署：读 [Deployment](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Deployment) 和 [Security](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Security)
- AI coding agents / vibe coding：优先读取 [Development](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Development)，再根据任务进入认证、管理或部署页面

## 运行

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m jstu_passkey.app
```

## 桌面 App 构建

仓库提供 `.github/workflows/build-desktop-apps.yml`，可生成包含 Python
运行时、依赖和前端资源的自包含程序：

- Windows x64：`Passkey-Auth-windows-x64.zip`
- Linux x64：`Passkey-Auth-linux-x64.tar.gz`
- macOS Intel：`Passkey-Auth-macos-x64.zip`
- macOS Apple Silicon：`Passkey-Auth-macos-arm64.zip`

在 GitHub Actions 中手动运行 `Build desktop apps` 后，可从该次运行的
**Artifacts** 下载。推送 `V*` 标签（例如 `V3.0.0`）时，产物还会自动附加到对应
GitHub Release。

桌面版本启动后会自动打开浏览器。数据库与固定的 Flask Session Secret 保存在
当前用户的应用数据目录，而不是临时打包目录：

- Windows：`%APPDATA%\Passkey-Auth`
- macOS：`~/Library/Application Support/Passkey-Auth`
- Linux：`${XDG_DATA_HOME:-~/.local/share}/Passkey-Auth`

构建产物未进行 Apple Developer ID 或 Windows Authenticode 签名，因此首次启动时
可能出现 Gatekeeper 或 SmartScreen 提示。正式公开分发时建议增加平台代码签名。

当前版本使用全新的 v2 数据结构，默认数据库为
`instance/passkeys-v2.sqlite3`。旧版 `passkeys.sqlite3` 不会自动迁移；如显式把
`PASSKEY_DATABASE` 指向旧库，应用会拒绝启动并提示使用新数据库。

## 用户管理

使用一次性 URL 创建首个或额外的全权限管理员：

```bash
PORT=5003 \
PASSKEY_ORIGIN=http://localhost:5003 \
.venv/bin/python -m jstu_passkey.app --reregister-admin qpwoeiruty
```

然后访问：

```text
http://localhost:5003/qpwoeiruty
```

通过反向代理部署时使用真实 HTTPS 地址访问；如需让开发服务器直接监听局域网，
另外设置 `HOST=0.0.0.0`，并确保 `PASSKEY_ORIGIN` 与浏览器实际 URL 完全一致。

恢复 token 只能使用 `A-Z`、`a-z`、`0-9`、`_`、`-`，长度为 8–128
字符，并且不能与 `api`、`demo`、`oauth`、`static`、`management`、
`_error` 等一级路由冲突。格式或路由冲突会在服务监听端口前输出醒目的启动错误并退出。

管理员创建成功后，一次性 URL 立即失效。登录后打开：

```text
http://localhost:5003/management
```

管理端支持：

- 用户、Passkey、`admin` / `login` / `demo` 权限及平台白黑名单
- OAuth Client 平台、回调地址、启停和 secret 轮换
- 注册永久开启、关闭或自定义期限临时开启
- 登录历史、管理审计、CSV 导出和日志清理
- 撤销用户会话、停用和删除用户

敏感管理写入除管理员 Session、CSRF 和最近一次 Passkey 验证外，还要求当前
`X-Action-Token`。该 token 的明文仅在登录或二次 Passkey 验证成功后返回给当前
浏览器；服务端只保存与用户及当前 Session 绑定的 hash。每次成功写入都会在 JSON
中返回 `next_action_token`，旧 token 立即失效；缺失或重放旧 token 会要求重新完成
Passkey 验证。只读 GET 接口不受影响。

CSV 使用 UTF-8 BOM 和稳定英文列名，不包含 credential 公钥、Client Secret
hash、session 或 token。登录历史包含原始 IP 和完整 User-Agent，应按部署地的隐私要求使用。

完整 OAuth 接入说明见：[OAuth 接入开发文档](docs/oauth-integration.md)。

然后打开：

```text
http://localhost:XXXX
```

如果本机 `XXXX` 端口被占用，可以换端口。WebAuthn 的 origin 必须和浏览器地址一致：

```bash
PORT=5001 PASSKEY_ORIGIN=http://localhost:5001 .venv/bin/python -m jstu_passkey.app
```

未设置 `PASSKEY_ORIGIN` 时，服务会自动使用当前请求地址，例如 `http://localhost:5002`。

Passkey / WebAuthn 要求安全上下文。`localhost` 属于浏览器允许的安全上下文；如果部署到线上，请使用 HTTPS，并把 `PASSKEY_RP_ID` 和 `PASSKEY_ORIGIN` 改成你的真实域名。

## 环境变量

默认配置集中在 `jstu_passkey/config.py`，运行时仍可通过环境变量覆盖：

```bash
PASSKEY_RP_ID=localhost
PASSKEY_ORIGIN=http://localhost:5000
PASSKEY_RP_NAME="JSTU Passkey"
PASSKEY_DATABASE=/path/to/passkeys-v2.sqlite3
FLASK_SECRET_KEY=change-me
PASSKEY_REGISTRATION_ENABLED=false
PASSKEY_HOME_AUTH_ENABLED=true
PASSKEY_SERVER_API_TOKEN=change-this-server-token
PASSKEY_OAUTH_CLIENT_ID=jstu-passkey-client
PASSKEY_OAUTH_CLIENT_SECRET=jstu-passkey-secret
PASSKEY_OAUTH_CLIENT_NAME="Passkey OAuth Client"
PASSKEY_OAUTH_REDIRECT_URIS=http://localhost:8765/api/auth/callback
PASSKEY_OAUTH_CHALLENGE_TTL_SECONDS=300
PASSKEY_TRUST_PROXY_HEADERS=false
PASSKEY_HTTP3_ALT_SVC=
PASSKEY_SERVER_TIMING_ENABLED=true
```

`PASSKEY_REGISTRATION_ENABLED` 默认关闭，仅作为新数据库尚未保存管理设置时的初始值。
之后可在 `/management` 中永久开启、关闭或按自定义到期时间临时开启。

`PASSKEY_HOME_AUTH_ENABLED` 默认开启，主页会加载 `main.js`，启用 Logo
隐藏注册/登录交互和对应快捷键。设为 `false` 后，主页仅展示品牌页面。

HTTP/3/QUIC 通常由 Caddy、NGINX、Cloudflare 等 HTTPS 反向代理终止，Flask 开发服务器本身不提供 HTTP/3。线上部署时设置 `PASSKEY_ORIGIN=https://auth.xxxxx`；如果代理会传递可信 `X-Forwarded-*` 头，再开启 `PASSKEY_TRUST_PROXY_HEADERS=true`。确认代理已经支持 HTTP/3 后，可设置 `PASSKEY_HTTP3_ALT_SVC='h3=":443"; ma=86400'` 让 HTTPS 响应宣告 HTTP/3 替代服务。

`PASSKEY_SERVER_TIMING_ENABLED` 默认开启，会发送低敏的 `Server-Timing: app;dur=...`，方便在 Chrome DevTools 的 Network 面板里查看 Flask 应用处理总耗时；不包含 WebAuthn、OAuth、用户或 token 内部细节。

## 服务端验证 API

浏览器中的 Passkey 登录和二次验证统一跳转到 `/auth/passkey` Logo 页面完成，
验证成功后再返回发起页面。旧的通用 `/api/login/options` 和
`/api/login/verify` 已删除，普通业务页面不能直接调用 WebAuthn 验证接口。

浏览器登录或二次验证成功后，前端接口返回登录结果和本次 Session 的 action token：

```json
{"ok": true, "mode": "login", "action_token": "..."}
```

action token 只用于同源浏览器发起敏感状态变更，不是身份信息或服务端 API token。

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
    "username": "alice",
    "createdAt": 1780000000
  }
}
```

`sub` 来自 WebAuthn user handle，适合作为 OAuth / SSO 场景里的稳定用户标识。这个接口默认只有设置了 `PASSKEY_SERVER_API_TOKEN` 且 Bearer token 匹配时才会返回身份信息。

## OAuth 与示例页面

启动后打开：

```text
http://localhost:5002/demo/oauth
```

流程：

1. OAuth Client 示例页面跳转到 `/oauth/authorize`
2. Passkey-Auth 展示极简 Logo 页面，并自动呼出 passkey 验证
3. 登录成功后回调到 `/demo/oauth/callback?code=...&state=...`
4. 示例回调后端使用 `client_id/client_secret/code/redirect_uri` 换取 token 和用户信息
5. 页面显示登录成功或失败

OAuth 相关端点：

```text
GET  /oauth/authorize
POST /oauth/authorize/complete
POST /oauth/token
GET  /oauth/userinfo
```

默认 OAuth client：

```text
client_id=jstu-passkey-client
client_secret=jstu-passkey-secret
redirect_uri=http://localhost:5002/demo/oauth/callback
```

如果你部署到其他域名或端口，设置 `PASSKEY_ORIGIN`，并用 `PASSKEY_OAUTH_CLIENT_ID`、`PASSKEY_OAUTH_CLIENT_SECRET` 和 `PASSKEY_OAUTH_REDIRECT_URIS` 配置生产 client。`PASSKEY_OAUTH_REDIRECT_URIS` 支持逗号或换行分隔多个精确 callback 地址。OAuth callback URL 里只携带必要的 `code/state`，不会携带 `username`。

本地开发时，默认 OAuth client 也允许 Hyping Web UI 的 callback：

```text
http://localhost:8765/api/auth/callback
```

如果 Hyping 使用了其他端口、域名或 HTTPS 地址，请把那个精确 callback URL 加到 `PASSKEY_OAUTH_REDIRECT_URIS`。

OAuth Client 首次从 `PASSKEY_OAUTH_CLIENT_*` 导入全新数据库，后续在
`/management` 中管理。旧的 `PASSKEY_OAUTH_DEMO_*` 配置不再读取。

## 第三方网页跳转和回调示例

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

## 链接跳转 Challenge 示例

启动后打开：

```text
http://localhost:5002/demo/link-login
```

这个示例模拟你描述的域名形态：

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
PASSKEY_OAUTH_REDIRECT_URIS=https://login.xxxxx/callback
PASSKEY_TRUST_PROXY_HEADERS=true
PASSKEY_HTTP3_ALT_SVC='h3=":443"; ma=86400'
```

`PASSKEY_RP_ID=xxxxx` 允许 `auth.xxxxx` 作为 passkey 的 RP 子域使用；浏览器实际打开 Auth WebUI 的 origin 必须和 `PASSKEY_ORIGIN` 一致。

## 可导入函数

核心函数在 `jstu_passkey.webauthn_service`：

- `build_registration_options(...)`
- `verify_registration(...)`
- `build_authentication_options(...)`
- `verify_authentication(...)`

Flask 服务只是其中一种使用方式。
