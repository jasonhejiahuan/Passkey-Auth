# 浏览器遥测与可插拔接收端

Passkey-Auth 内置可选、默认关闭的浏览器遥测。它面向管理员做兼容性和设备分布
分析，不参与登录判断，也不会改变 WebAuthn、OAuth 或 Session 的信任边界。

## 性能模型

总开关保存在认证主库的 `app_settings`，启动时加载进内存。关闭后，每个响应只经过
一次内存布尔短路，随后立即返回：

- 不查询遥测设置或用户策略；
- 不打开独立遥测数据库；
- 不读取或重写 HTML 响应体；
- 不注入 `/static/telemetry.js`；
- 浏览器不下载模块、不执行采集、不创建网络任务。

启用后，服务端会在发送 HTML 前用内存策略判断当前 Session 用户。用户策略为
“关闭”时不下发脚本；“自定义”时只把所选能力写入脚本配置。未登录访客只有在
“允许未登录访客”开启时才会收到默认策略。

接收端与发送路径是两个独立配置：

- 接收端：内置 Telemetry、jason-telemetry、自定义 HTTP POST；
- 发送路径：浏览器直接发送、Passkey-Auth 服务端转发。

默认是“内置 + 服务端接收”。未选中的外部适配器不会导入、创建线程或建立连接。
外部服务端转发模式只在第一条有效样本到达时创建一个容量为 128 的后台队列；HTTP
响应不等待外部服务器，队列满时丢弃新样本而不拖慢登录页面。外部浏览器直连模式
不让样本经过 Passkey-Auth，因此进一步节省其上行带宽和 CPU。

## 浏览器执行

采集脚本使用 `requestIdleCallback()`，并为不支持的浏览器提供短延迟
`setTimeout()` 回退。内置和服务端转发模式通过同源 `navigator.sendBeacon()`
异步发送；排队失败时才使用 `fetch(..., keepalive: true)`。直连模式先从同源
Passkey-Auth 取得目标描述，再向外部接收端发送。页面不会打开窗口或 iframe，也
不会等待遥测完成后再展示或跳转。

字体探测按操作系统动态导入：

- Windows 只下载 Windows 字体候选模块；
- macOS / iOS 只下载 Apple 字体候选模块；
- Linux / ChromeOS 只下载 Linux 字体候选模块。

电池模块仅在管理员启用且浏览器实际提供 `navigator.getBattery()` 时下载。Safari
目前不提供 Battery Status API，也不提供 User-Agent Client Hints 的高熵硬件提示，
因此这些字段会直接省略或标记为不支持，不会增加额外等待。

现代浏览器不会向普通网页提供可靠的精确 CPU 型号。硬件摘要只记录
`hardwareConcurrency`、粗粒度 `deviceMemory`，以及浏览器愿意提供的架构、位数或
设备型号提示。

## 数据与安全

每个 HTML 响应使用 Flask Secret 签发一个 5 分钟有效的采集 token。token 绑定：

- 随机一次性 ID；
- 当前用户 ID（或匿名）；
- 当前能力列表；
- 当前内存策略版本。

采集端点或直连目标签发端点会重新检查总开关和策略。内置模式用数据库唯一约束
阻止重放；外部模式在 token 有效期内用内存一次性表阻止重复签发或转发。该 token
只能提交遥测，不能作为登录、OAuth、Management 或用户身份证明。

遥测数据库默认位于：

```text
instance/passkeys-telemetry-v1.sqlite3
```

可通过 `PASSKEY_TELEMETRY_DATABASE` 修改。它不保存原始 IP，而保存由服务器密钥
生成的短哈希；不生成稳定的浏览器 fingerprint。管理员仍应把字体、硬件、电池、
网络和导出 CSV 视为可能具有识别性的运营数据，并按部署地要求设置通知、合法依据
和保留期限。

外部模式不会打开该 SQLite 文件，也不会为了本页统计重复保存外部事件。

## jason-telemetry

jason-telemetry v12 已提供任意 JSON 写入接口、一次性浏览器采集 token 和
`device-info-submit`，所以日常数据路径继续使用原有 `/v12/...` API：

- 服务端转发：`POST /v12/{api_key}/telemetry`；
- 浏览器直连：Passkey-Auth 用服务端 API Key 创建一次性 token，浏览器只得到
  `/v12/browser/{token}/device-info-submit`。

浏览器使用 `text/plain` 发送 JSON 文本，v12 会按已有 raw-body 回退解析，因此不
需要向浏览器暴露 API Key，也不需要修改原 v12 数据 API。

可选的
`integrations/jason-telemetry/telemetry_server_v13_both.py`
在完整复制 v12 的基础上增加自动配对端点，同时保留所有 `/v12/...` 路由和行为。
启动时会打印一个默认 5 分钟有效、只能使用一次的配对码；也可在运行时控制台输入
`pairing` 生成新码。Management 只需填写 v13 地址和该配对码，Passkey-Auth 与
jason-telemetry 会用双 nonce + HMAC challenge-response 自动创建专用
`read,write` API Key。最终 API Key 只在服务端连接中返回一次，不进入浏览器响应。

配对必须经过 HTTPS，只有 `127.0.0.1` / `::1` 允许 HTTP。相关环境变量：

```text
TELEMETRY_PASSKEY_PAIRING_ENABLED=true
TELEMETRY_PASSKEY_PAIRING_TTL_SECONDS=300
TELEMETRY_PASSKEY_PAIRING_CHALLENGE_TTL_SECONDS=120
TELEMETRY_PASSKEY_PAIRING_CODE=
TELEMETRY_PASSKEY_PAIRING_STATE_FILE=passkey_pairing_state.json
```

服务端只持久化已消费配对码的 SHA-256 派生摘要，不持久化配对码明文；因此即使使用
固定环境变量配对码，服务重启后也不会重新接受已经使用过的值。

## 自定义 HTTP

服务端转发支持无认证、Bearer Token、自定义私有 Header 和最多 12 个附加 Header。
私有值仅由服务端发送。浏览器直连只能使用无认证端点：

- `text/plain`：不触发常规 CORS 预检，接收端需要把 body 解析为 JSON；
- `application/json`：接收端必须正确配置 CORS；
- 直连 Header 不得包含 Authorization、API Key、token、secret 或 Cookie。

自定义目标由管理员明确配置，可能访问内网地址；应只授予受信管理员 Management
权限，并把该配置视为具有服务端请求能力的敏感设置。

## Management

“遥测”页面按需加载，不会让普通用户、平台、日志或设置页面等待统计查询。面板提供：

- 总开关、匿名访客开关、默认能力和 7–365 天保留期；
- 接收端、发送路径、超时、连接测试和 jason-telemetry v13 自动配对；
- 每个用户的继承、关闭或自定义能力策略；
- 总样本、24 小时样本、已识别用户和平均载荷；
- 操作系统、浏览器、设备类型和能力分布；
- 最近样本详情、CSV 导出和按日期清理。

统计、CSV 和清理只适用于内置模式。外部模式显示当前队列状态或直连状态，样本查询
和可视化由外部接收端负责。

所有配置和清理写操作继续要求管理员 Session、CSRF、最近 5 分钟 Passkey
reauth，以及当前 rotating action token。

## 浏览器 API 参考

- [Beacon API](https://developer.mozilla.org/en-US/docs/Web/API/Navigator/sendBeacon)
- [requestIdleCallback](https://developer.mozilla.org/en-US/docs/Web/API/Window/requestIdleCallback)
- [Battery Status API](https://developer.mozilla.org/en-US/docs/Web/API/Battery_Status_API)
- [User-Agent Client Hints](https://developer.mozilla.org/en-US/docs/Web/API/User-Agent_Client_Hints_API)
