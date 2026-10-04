# OAuth 接入开发文档

Passkey-Auth 负责身份认证，业务应用负责自己的 Session、角色、Team 和业务权限。身份的 `sub` 是持久随机标识，重命名不会改变；不要用用户名作为外键。本服务提供 OAuth authorization code，不是 OIDC，不签发 ID Token。

## 配置

Cloudflare 初始化见 [部署文档](cloudflare-native.md)。`PASSKEY_RP_ID`、`PASSKEY_ORIGIN`、`PASSKEY_RP_NAME` 在 Worker 配置中；服务端 Session Verify 的随机 `PASSKEY_SERVER_API_TOKEN` 放 Worker Secret。OAuth Client 在 Management 中创建，回调地址逐条精确匹配，Secret 仅在创建／轮换时显示一次。公开注册默认关闭，可在 Management 临时或持续打开。

不存在 Flask Secret、SQLite 路径或 Linux 代理配置。会话、授权码、访问令牌都在 D1 中以哈希索引保存。客户端应将它们视为不透明字符串。

## OAuth authorization code

发现入口：`GET /.well-known/oauth-authorization-server`。返回 issuer、authorization_endpoint、token_endpoint、userinfo_endpoint、支持的 `code`／`authorization_code`、`client_secret_post`／`client_secret_basic`、S256 和注册提示支持情况。

1. 业务后端创建随机 `state`、43–128 字符的 PKCE verifier，保存在自己的会话。计算 `BASE64URL(SHA256(verifier))`。
2. 跳转到 `GET /oauth/authorize`。
3. Passkey-Auth 在原有 UI 完成 Passkey 验证后，将 `code` 和 `state` 回跳到已登记地址。
4. 业务后端精确验证 `state`，使用 Client Secret 和 verifier 换取 Token，建立自己的业务登录态。

| 授权参数 | 要求 |
| --- | --- |
| `response_type` | 固定 `code` |
| `client_id` | 已启用客户端 |
| `redirect_uri` | 与已登记值完全相同 |
| `state` | 必填，最多 512 字符；消费方自己验证 |
| `code_challenge` / `code_challenge_method` | 新接入始终使用 S256；保留旧非 PKCE 保密客户端兼容 |
| `screen_hint` | 可选 `signup` |
| `login_hint` | 可选用户名；`signup` 时必填 |

`screen_hint=signup` 配合 `login_hint`：新用户名进入创建 Passkey；用户名已存在时要求该用户的新一次 Passkey 验证，复用原 `sub`。这不会仅根据已有 Cookie 把身份关联给另一个账号。新注册关闭时，仍可验证已存在身份。

`POST /oauth/token` 接受 JSON 或 `application/x-www-form-urlencoded`：

```json
{
  "grant_type": "authorization_code",
  "client_id": "your-client",
  "client_secret": "your-server-secret",
  "code": "returned-code",
  "redirect_uri": "https://app.example.com/api/auth/callback",
  "code_verifier": "original-verifier"
}
```

也可用 HTTP Basic 传 Client ID／Secret。成功为 HTTP 200：

```json
{
  "ok": true,
  "access_token": "opaque-token",
  "token_type": "Bearer",
  "expires_in": 3600,
  "authenticated": true,
  "user": { "sub": "stable-random-id", "id": 1, "username": "Jason", "createdAt": 1790000000 }
}
```

`GET /oauth/userinfo` 使用 `Authorization: Bearer <access_token>`，返回同样的 user 对象。令牌每次使用都会核对当前用户状态、会话版本、平台状态及平台权限；停用／撤权不会等到 Token 自然过期才生效。

授权码有效期 300 秒，一次性消费；访问令牌有效期 3600 秒。错误 PKCE 不会提前烧掉合法授权码；两个并发合法兑换最多一个成功。`invalid_client` 返回 401，`invalid_grant`／`unsupported_grant_type` 返回 400，无效 userinfo Token 返回 401。错误 JSON 保留 `error`／`error_description` 语义。

不可信 Client 或不匹配的回调不会获得错误重定向。已确认合法回调后，错误带 `error`、`error_description`、`state`。兼容旧 Hyping：未采用 PKCE／注册提示的 `/api/auth/callback` 在浏览器认证错误时使用同源 `/api/auth/error`；现代 PKCE／注册流程仍回到原始精确 callback。

浏览器内部 `POST /oauth/authorize/complete` 保留 `{client_id,redirect_uri,state}` 与 `{ok,redirectUrl}`；它只完成当前 Session 中经过新 Passkey 验证的请求，不能代替第三方后端 Token 兑换。

## Link challenge

原 Python 可导入的创建／消费函数由两个服务器 HTTP 接口承接，避免业务应用依赖认证数据库或签名实现。原 Demo 与 `/oauth/challenge/{id}` URL 不变。原 Python 模块的调用方只需把创建与消费操作替换为下列请求；PPQ 使用标准 OAuth，因此无需为此更改。

两个接口接受 Client HTTP Basic，或 JSON 中 `client_id`／`client_secret`。只允许服务端调用，Secret 不进入浏览器。

`POST /api/server/challenges`：

```json
{ "client_id": "your-client", "client_secret": "server-secret", "return_uri": "https://app.example.com/callback", "username": "Jason", "state": "random-state" }
```

返回 `{ok:true,challenge,authorizationUrl,expires_in:300}`。后端保存 `challenge`、state、callback，浏览器访问 `authorizationUrl`。认证页面要求对应用户名的新一次 Passkey 验证；成功回跳带 `challenge`、`challenge_result`、`state`、`status=success`。

业务后端验证 state，然后 `POST /api/server/challenges/consume`：

```json
{ "client_id": "your-client", "client_secret": "server-secret", "challenge": "saved-id", "challenge_result": "returned-result", "state": "saved-state", "return_uri": "https://app.example.com/callback" }
```

成功为 `{ok:true,authenticated:true,user:{sub,id,username,createdAt}}`。有效期、Client、回调、state、身份版本、权限和结果哈希必须全部匹配，并在同一事务内一次消费。`status=success` 本身从来不是认证凭据。新内部结果 Token 为高熵不透明凭据，不再需要第三方持有服务的签名密钥。

## 服务端 Session Verify

`POST /api/server/session/verify`，要求 `Authorization: Bearer <PASSKEY_SERVER_API_TOKEN>`。接受：

```json
{ "sessionCookie": "opaque-cookie-value" }
```

也兼容 `session_cookie`、包含 `session=...` 的 Cookie 字符串；空请求体验证该请求携带的 Session Cookie。成功返回 `{ok:true,authenticated:true,user:{sub,id,username,createdAt}}`，没有有效登录则为 `{ok:true,authenticated:false}`，无效指定 Cookie 会附带错误。缺少／错误服务器令牌返回 401。

不要尝试解析 Cookie，也不要把服务端凭据放到前端、日志、截图或 URL。普通浏览器 `GET /api/me` 仍只返回 `{authenticated,user:{username}}`。

## 接入变更与边界

- 新部署重新创建测试用户、Passkey 与 Client，旧 Cookie／Token 无需兼容。
- Client ID、回调、HTTP 方法、核心返回结构及 OAuth 错误语义保持；PPQ 无需更改。
- 浏览器写入要求同源 Origin；跨站业务应用通过后端 OAuth 接口接入，不直接调用注册或 Management 写接口。
- 用户名采用 NFKC 和 Unicode 小写归一化判重，仍最多 64 字符；接受普通空格，拒绝控制字符和其他空白。稳定身份是 `sub`。
- 恢复注册必须用户验证，普通登录按管理员设定。Management 的近期认证只认实际 UV 成功。
- Demo 结果页保留布局，但对有效 Code、Token 和 Secret 脱敏。
- 不提供密码登录、隐式授权、refresh token、开放跳转或任意 Origin CORS。

实现索引：`worker/src/auth.ts`、`oauth.ts`、`management.ts`、`store.ts`、`worker/migrations/`。正常开发用 `npm run dev`；API 安全回归在真实 workerd/D1 上运行。

### Authorization failures

For a validated redirect URI, `/oauth/authorize` returns `error=registration_not_allowed`
when `screen_hint=signup` names a new identity and registration is closed. The
original `state` is preserved. An existing identity can still authenticate while
registration is closed. A gate closed during the ceremony produces the same code;
`/api/register/options`, `/api/register/verify` and `/api/ui/intent` include it in
JSON as `code` alongside their existing human-readable `error` and HTTP 403.

The OAuth UI reports `access_denied` for a dismissed Passkey prompt,
`authentication_failed` for verification failures, and `server_error` or
`temporarily_unavailable` for provider/network failures. Clients must validate and
consume their browser-bound state before displaying any callback error, use an
allowlist of codes, and never present all failures as user cancellation. Do not
render upstream HTML bodies or raw error descriptions. No callback path, token
exchange, stable subject, scope, PKCE or legacy error-return routing changed.
