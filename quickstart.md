# Quick Start

快速开始指南，帮助你在本地运行 Passkey Auth 应用。

## 初始设置

### 1. 创建虚拟环境并安装依赖

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

### 2. 启动应用（基础模式）

```bash
.venv/bin/python -m jstu_passkey.app
```

应用默认监听 `http://localhost:5003`

## 常见启动场景

### 场景 1：自定义端口

```bash
PORT=5003 .venv/bin/python -m jstu_passkey.app
```

然后访问 `http://localhost:5003`

### 场景 2：创建首个管理员（带一次性 token）

```bash
PORT=5003 \
PASSKEY_ORIGIN=http://localhost:5003 \
.venv/bin/python -m jstu_passkey.app --reregister-admin qpwoeiruty
```

然后访问：

```text
http://localhost:5003/qpwoeiruty
```

**重要**：一次性 URL 仅能使用一次，创建管理员后立即失效。

### 场景 3：本地网络访问（局域网）

```bash
PORT=5003 \
HOST=0.0.0.0 \
PASSKEY_ORIGIN=http://<YOUR_LOCAL_IP>:5003 \
.venv/bin/python -m jstu_passkey.app
```

替换 `<YOUR_LOCAL_IP>` 为你的本机局域网 IP（如 `192.168.1.100`）。

**重要**：`PASSKEY_ORIGIN` 必须与浏览器实际访问的 URL 完全一致（用于 WebAuthn 安全验证）。

### 场景 4：本地 HTTPS 反向代理（局域网 / 手机测试）

```bash
.venv/bin/python -m jstu_passkey.local_https_proxy
```

启动器会自动检测本机局域网 IP，生成自签名证书，并输出可访问的
`https://<YOUR_HOSTNAME>.local:5443` origin。后端 Flask 服务仍只监听
`127.0.0.1:5003`，HTTPS 代理会转发到后端，并在启动输出里显示检测到的局域网 IP。
代理会设置：

- `PASSKEY_ORIGIN=https://<YOUR_HOSTNAME>.local:5443`
- `PASSKEY_TRUST_PROXY_HEADERS=true`
- `PASSKEY_SECURE_COOKIES=true`
- `PASSKEY_HSTS_MAX_AGE_SECONDS=0`

创建首个管理员时也可以直接走 HTTPS 反代：

```bash
.venv/bin/python -m jstu_passkey.local_https_proxy --reregister-admin qpwoeiruty
```

如果自动检测的 `.local` 主机名不适合当前网络，或你希望使用 hosts / 本地域名：

```bash
.venv/bin/python -m jstu_passkey.local_https_proxy \
  --origin https://passkey.local:5443
```

浏览器会提示自签名证书不受信任，这是本地测试的预期行为。WebAuthn 不接受裸 IP 作为
Passkey RP ID；如果显式传入 `https://<IP>:5443`，启动器会拒绝启动。请确保地址栏
origin、证书 SAN 和 `PASSKEY_RP_ID` 指向同一个域名。

### 场景 5：HTTPS 反向代理部署

```bash
PORT=5003 \
PASSKEY_ORIGIN=https://example.com \
PASSKEY_TRUST_PROXY_HEADERS=true \
PASSKEY_PROXY_FIX_X_PROTO=1 \
.venv/bin/python -m jstu_passkey.app
```

- `PASSKEY_TRUST_PROXY_HEADERS=true`：信任反向代理注入的 `X-Forwarded-*` 头
- `PASSKEY_PROXY_FIX_X_*`：代理链中可信 hop 数（通常为 1）

### 场景 6：自定义数据库路径

```bash
PASSKEY_DATABASE=/path/to/custom.sqlite3 \
.venv/bin/python -m jstu_passkey.app
```

默认数据库位置：`instance/passkeys-v2.sqlite3`

### 场景 7：测试模式（启用注册）

```bash
PORT=5003 \
PASSKEY_ORIGIN=http://localhost:5003 \
PASSKEY_REGISTRATION_ENABLED=true \
.venv/bin/python -m jstu_passkey.app
```

## 常见环境变量

| 环境变量 | 默认值 | 说明 |
|---------|--------|------|
| `PORT` | `5000` | HTTP 监听端口 |
| `HOST` | `localhost` | HTTP 监听地址 |
| `PASSKEY_ORIGIN` | 自动检测 | WebAuthn origin（必须与浏览器 URL 一致）；为空时使用当前请求 origin |
| `PASSKEY_RP_ID` | `localhost` | WebAuthn RP ID（通常是根域名） |
| `PASSKEY_RP_NAME` | `JSTU Passkey` | WebAuthn 弹窗显示的服务名称 |
| `PASSKEY_REGISTRATION_ENABLED` | `false` | 是否默认开放注册 |
| `PASSKEY_REGISTRATION_UNLOCK_TTL` | `120` | 注册解锁有效期（秒） |
| `PASSKEY_DATABASE` | 空（使用默认） | SQLite 数据库路径 |
| `PASSKEY_TELEMETRY_DATABASE` | 空（使用默认） | 独立遥测 SQLite 数据库路径 |
| `FLASK_SECRET_KEY` | 随机生成 | Flask session 签名密钥；生产环境请设置固定值 |
| `PASSKEY_SERVER_API_TOKEN` | 空 | 服务端会话验证 API 的 Bearer token |
| `PASSKEY_OAUTH_CLIENT_ID` | `jstu-passkey-client` | OAuth client ID |
| `PASSKEY_OAUTH_CLIENT_SECRET` | `jstu-passkey-secret` | OAuth client secret；生产环境请改强随机值 |
| `PASSKEY_OAUTH_CLIENT_NAME` | `Passkey OAuth Client` | OAuth client 名称 |
| `PASSKEY_OAUTH_REDIRECT_URIS` | 空 | 额外允许的 OAuth callback URI（逗号或换行分隔） |
| `PASSKEY_OAUTH_CODE_TTL` | `300` | OAuth authorization code 有效期（秒） |
| `PASSKEY_OAUTH_ACCESS_TOKEN_TTL` | `3600` | OAuth access token 有效期（秒） |
| `PASSKEY_OAUTH_CHALLENGE_TTL` | `300` | Link challenge 有效期（秒） |
| `PASSKEY_TRUST_PROXY_HEADERS` | `false` | 是否信任反向代理的 `X-Forwarded-*` 头 |
| `PASSKEY_PROXY_FIX_X_FOR` | `1` | `X-Forwarded-For` 可信 hop 数 |
| `PASSKEY_PROXY_FIX_X_PROTO` | `1` | `X-Forwarded-Proto` 可信 hop 数 |
| `PASSKEY_PROXY_FIX_X_HOST` | `1` | `X-Forwarded-Host` 可信 hop 数 |
| `PASSKEY_HTTP3_ALT_SVC` | 空 | HTTP/3 Alt-Svc 响应头值 |

遥测默认关闭。创建管理员并登录 `/management` 后，在“遥测”中开启总开关、
选择默认采集能力，并按用户设置继承、关闭或自定义策略。接收端默认为内置
Telemetry，也可选择 jason-telemetry 或自定义 HTTP POST；外部接收端可选择浏览器
直连或服务端异步转发。关闭总开关时不会加载遥测 JS、外部适配器或遥测数据库。
更多说明见 [遥测文档](docs/telemetry.md)。

## 用户注册

### 前置条件：启用注册功能

注册默认**关闭**。要启用注册，有两种方式：

#### 方式 1：启动时启用注册（推荐开发）

```bash
PORT=5003 \
PASSKEY_ORIGIN=http://localhost:5003 \
PASSKEY_REGISTRATION_ENABLED=true \
.venv/bin/python -m jstu_passkey.app
```

#### 方式 2：通过管理面板启用（生产推荐）

1. 首先创建管理员账户（见下文）
2. 登录管理面板：`http://localhost:5003/management`
3. 进入 **注册管理** 设置
4. 选择注册模式：永久开启、自定义期限或关闭

### 注册流程（用户操作）

1. **访问首页**
   ```
   http://localhost:5003
   ```

2. **点击"注册"按钮**
   - 浏览器可能提示缺少 Passkey（这是正常的，继续）

3. **输入用户名**
   - 长度 1-64 字符
   - 不能与已注册用户名重复

4. **创建 Passkey**
   - 浏览器弹出 WebAuthn 认证器弹窗
   - 选择创建方式：
     - **Windows**：使用 Windows Hello 或安全密钥
     - **macOS**：使用 Touch ID/Face ID 或安全密钥
     - **iOS/Android**：使用生物识别或屏幕锁定

5. **完成注册**
   - 成功后会自动登录
   - 用户名、Passkey 和登录信息已保存

### 注册后：登录

1. **访问首页**
   ```
   http://localhost:5003
   ```

2. **点击"登录"按钮**

3. **选择登录方式**
   - **用户名登录**：输入用户名，浏览器提示使用 Passkey
   - **无用户名登录**：直接使用 Passkey（跳过用户名输入）

4. **通过 Passkey 认证**
   - 浏览器弹出 WebAuthn 认证器弹窗
   - 使用生物识别或屏幕锁定确认身份

5. **登录成功**
   - 用户已认证，可访问应用功能

### 常见问题

#### "注册功能未启用"

**症状**：点击注册后报错

**原因**：
- 应用未设置 `PASSKEY_REGISTRATION_ENABLED=true`
- 或管理员未在管理面板启用注册

**解决**：
```bash
# 方案 1：启动时启用
PASSKEY_REGISTRATION_ENABLED=true .venv/bin/python -m jstu_passkey.app

# 方案 2：通过管理面板（需要管理员权限）
# 登录 /management，进入注册管理，启用注册
```

#### "用户名已注册"

**症状**：注册时报错 "用户名已注册"

**原因**：该用户名已被其他账户占用

**解决**：选择其他用户名

#### WebAuthn 认证器不可用

**症状**：浏览器弹窗后显示"无可用认证器"

**原因**：
- 浏览器不支持 WebAuthn（使用现代浏览器：Chrome、Safari、Firefox、Edge）
- 设备不支持 Passkey（如虚拟机）
- 浏览器隐私模式可能禁用 Passkey

**解决**：
- 更新浏览器到最新版本
- 使用支持 WebAuthn 的设备
- 退出隐私/无痕模式
- 使用外部安全密钥（YubiKey、Titan Key）

#### "注册入口未解锁或已过期"

**症状**：注册时报错

**原因**：
- 注册入口自动锁定（默认锁定时间 120 秒）
- 刷新页面后过期

**解决**：重新访问首页，重新点击注册按钮

## 运行测试

```bash
.venv/bin/python -m unittest discover -s tests -v
```

## 管理员账户

### 创建首个管理员

使用一次性 URL 创建首个管理员：

```bash
PORT=5003 \
PASSKEY_ORIGIN=http://localhost:5003 \
.venv/bin/python -m jstu_passkey.app --reregister-admin <your-token>
```

访问 `http://localhost:5003/<your-token>` 创建管理员账户。

**Token 要求**：
- 仅支持 `A-Z`、`a-z`、`0-9`、`_`、`-`
- 长度 8–128 字符
- 不能与一级路由冲突：`api`、`demo`、`oauth`、`static`、`management`、`_error`

### 登录管理面板

管理员创建后访问：

```text
http://localhost:5003/management
```

## 数据库

### v2 数据库

当前版本使用全新 v2 数据结构，默认数据库为：

```
instance/passkeys-v2.sqlite3
```

### 数据库迁移

旧版 `passkeys.sqlite3` **不会自动迁移**。如果显式设置 `PASSKEY_DATABASE` 指向旧库，应用会**拒绝启动**并提示使用新数据库。

## 浏览器兼容性

支持所有现代浏览器的 WebAuthn 功能：

- Chrome / Chromium
- Safari
- Firefox
- Edge

## 更多文档

- **OAuth 接入**：见 [Authentication Flows](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Authentication-Flows)
- **生产部署**：见 [Deployment](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Deployment)
- **安全模型**：见 [Security](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Security)
- **Agent 指南**：见 [Development](https://github.com/jasonhejiahuan/Passkey-Auth/wiki/Development)

## 常见问题

### WebAuthn 认证失败（origin mismatch）

**症状**：浏览器报错 "SecurityError: DOMException"

**原因**：`PASSKEY_ORIGIN` 与浏览器实际 URL 不一致

**解决**：确保 `PASSKEY_ORIGIN` 与地址栏 URL 完全匹配（协议、域名、端口）

### 端口被占用

```bash
PORT=5001 .venv/bin/python -m jstu_passkey.app
```

改用其他端口，同时更新 `PASSKEY_ORIGIN`。

### 虚拟环境激活出错

如果 `.venv/bin/python` 找不到，尝试重新创建虚拟环境：

```bash
rm -rf .venv
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```
