# Passkey Auth

JASON Studio 的 Passkey 认证服务。当前服务器完全运行在 Cloudflare Workers 与 D1 上；沿用现有 Logo、HTML、CSS 和原生浏览器交互，不依赖 VPS 或外部认证后端。

- 自定义用户名注册、用户名及无用户名登录、同一账号添加多个 Passkey，以及逐凭据停用和删除。
- OAuth authorization code、S256 PKCE、自助注册接入、link challenge 和服务端会话验证。
- Management 用户与平台权限、会话撤销、管理员恢复、审计、统计和 CSV。
- CSRF、近期 Passkey 重新验证、轮换操作令牌、签名管理通道。
- 默认关闭的可选遥测，保留内置、Jason、custom 后端及逐用户策略。

## 开始

```sh
cd worker
npm ci
npm run db:local
npm run operator -- demo-client --origin http://localhost:8787
npm run operator -- recovery --origin http://localhost:8787
npm run dev
```

恢复入口保存在命令显示的本地私密文件里。访问它、选择用户名并创建 Passkey，即可建立管理员。公开注册默认关闭，没有“第一个注册者自动成为管理员”的逻辑。

[Cloudflare 初始化与架构](docs/cloudflare-native.md) · [OAuth 接入](docs/oauth-integration.md) · [遥测](docs/telemetry.md)

```sh
npm run typecheck
npm test
npm run build
```

测试在真实 workerd／D1 运行环境中验证事务与安全语义，并保存原页面渲染基线。云端性能、浏览器回归和免费额度验证以 [交付验证记录](docs/cloudflare-validation.md) 为准。

## 代码与运行边界

`worker/` 是支持的服务器实现。`jstu_passkey/templates/`、`static/` 和注册脚本继续作为原界面的单一来源，构建时复制／预编译，不需要 Python 运行时。

旧 Python、桌面与本地 HTTPS 工具留作独立历史工作流，使用各自的本地身份库；不会连接或替代 Cloudflare。桌面构建仅保留手动入口，Linux 生产部署路径已退役。详见 [旧版说明](docs/legacy-python.md)。新环境不导入旧测试身份、Passkey 或 Token。

## AI 协作声明

本项目由仓库所有者与 OpenAI Codex 协作开发。该声明由仓库所有者主动保留，用于透明记录 AI-assisted development；项目授权、免责声明和责任限制以 Apache License 2.0 为准。贡献范围见 [AI_ATTRIBUTION.md](AI_ATTRIBUTION.md)。
