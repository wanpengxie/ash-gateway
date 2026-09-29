# ash gateway

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/wanpengxie/ash-gateway)

自部署的 Cloudflare Worker + Durable Object 网关，让你在任何地方安全地连回自己手机上的 **ash** 个人 Agent。

- **每人一套，部署在你自己的 Cloudflare 账户**。项目方不托管网关，也不经手你的消息、密钥或账户。
- **手机和客户端都只发起出站 WSS**。不需要公网 IP、端口映射或 Tunnel，免费的 `workers.dev` 域名就够用。
- **网关只做发现和转发**：保存设备公钥、授权和撤销记录；不保存对话、记忆、文件，也不排队离线任务。手机不在线时，发送方会明确收到 `device_offline`。
- **授权的根在手机上**：新设备必须经手机确认才能配对；每条消息都由发送方签名，由接收方验签。网关本身不是最终的授权者。

> English: a self-hosted relay (one Worker + one SQLite-backed Durable Object with hibernatable WebSockets) between an ash agent phone and the user's other devices. It stores only public keys and grants — never conversations — and every state change is signed by the phone.

## 架构

```text
你的 Cloudflare 账户
  https://ash-gateway.<你的子域>.workers.dev
                │
        Worker：路由、Origin 检查、请求体大小限制
                │
        GatewayHub（1 个 SQLite DO）：认领、挑战/会话、配对、撤销、WSS 转发
                │
      ┌─────────┴─────────┐
      │ WSS               │ WSS
 ash 手机（owner）      电脑 / 网页 / 其他手机（client）
```

## 部署（首版：从 GitHub 部署，再手动接到 APK）

1. **生成认领密钥**：先准备一个随机串，例如 `openssl rand -base64 32`。之后 ash App 会提供生成入口。
2. **点上面的 Deploy to Cloudflare 按钮**，登录你自己的 Cloudflare 账户，填写 `BOOTSTRAP_SECRET`。按钮会从本仓库构建，自动创建 Worker 和 `GatewayHub` Durable Object。
   - 也可以手动部署：`npm ci && npx wrangler deploy && npx wrangler secret put BOOTSTRAP_SECRET`
3. 打开 `https://ash-gateway.<子域>.workers.dev/v1/health`，看到 `"claimed": false, "bootstrap_configured": true` 就说明部署好了。
4. **在 ash App 里填网关地址和同一个认领密钥**。手机用自己的硬件密钥完成首次认领（HMAC 证明知道密钥 + 签名证明持有私钥）。**认领只能成功一次**，之后可以在 Cloudflare 控制台删掉这个 Secret。
5. **添加设备**：手机上生成配对二维码（网关地址 + 一次性票据 + 手机公钥指纹）→ 新设备提交配对申请 → 手机上确认设备指纹和权限 → 完成。

**手机丢了怎么办**：在 Cloudflare 控制台把变量 `RESET_EPOCH` 改成一个新值（比如 `1`）后重新部署，网关会清空全部设备和授权，等待重新认领。能做这件事的只有 Cloudflare 账户的持有者，任何公网请求都触发不了重置。

## 协议

完整规范见 [docs/PROTOCOL.md](docs/PROTOCOL.md)，参考实现见 [client/client.ts](client/client.ts)。

| 接口 | 作用 |
|---|---|
| `GET /v1/health` | 部署状态：是否已认领、手机是否在线 |
| `POST /v1/bootstrap/challenge` → `POST /v1/bootstrap/claim` | 手机首次认领（一次性） |
| `POST /v1/auth/challenge` → `POST /v1/auth/session` | 已登记设备用签名换一个 15 分钟有效的会话 |
| `GET /v1/ws` | 已鉴权的 WebSocket（先鉴权，后 Upgrade） |
| `POST /v1/pair/request` / `POST /v1/pair/status` | 新设备凭二维码票据申请配对，并查询手机的批准结果 |

## 开发

```bash
npm ci
npm test                        # 协议单元测试（含 Android DER 签名互通）
cp .dev.vars.example .dev.vars   # 填一个 BOOTSTRAP_SECRET
npm run dev                     # wrangler dev，本地 http://127.0.0.1:8787
GATEWAY_URL=http://127.0.0.1:8787 BOOTSTRAP_SECRET=... npm run e2e
```

`npm run e2e` 会同时扮演手机和电脑，覆盖认领、重放、配对、签名转发、伪造发送方、离线和撤销，共 33 项检查。它会用一把临时密钥认领网关，所以**不要对你真正要给手机用的网关跑**；要跑就用单独部署的测试实例，或者跑完后用 `RESET_EPOCH` 重置。

## 免费额度

- 必须使用 Hibernation WebSocket API：DO 空闲时休眠，只在处理事件时计时。
- 协议级 ping 由运行时自动应答，不唤醒 DO；应用层的 `"ping"` 文本也配置了自动回复 `"pong"`。
- 不使用 Alarm 或定时器，也不保持常驻连接。
- 入站 WS 消息按 20:1 折算 DO 请求数。

公网入口无法防止有人故意耗尽你账户的免费额度。网关对挑战数量、配对票据、帧大小和请求体大小做了限制，这项剩余风险在此如实说明。

## 当前不包含

- **端到端加密**：V1 只有 TLS 加消息签名，Cloudflare 在转发时能看到明文。E2EE 是公开发布前的安全里程碑。
- **手机直部署**：由 App 通过 OAuth 替你部署。
- **Device Link**：电脑端注册能力，由手机反向调用。
- **一个账户多台 Agent 手机**。

## 许可

MIT
