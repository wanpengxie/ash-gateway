# ash gateway

[![Deploy to Cloudflare](https://deploy.workers.cloudflare.com/button)](https://deploy.workers.cloudflare.com/?url=https://github.com/wanpengxie/ash-gateway)

自部署的 Cloudflare Worker + Durable Object 网关，让你在任何地方安全地连回自己手机上的 **ash** 个人 Agent。

- **每人一套，部署在你自己的 Cloudflare 账户**。项目方不托管网关，也不经手你的消息、密钥或账户。
- **手机和客户端都只发起出站 WSS**。不需要公网 IP、端口映射或 Tunnel，免费的 `workers.dev` 域名就够用。
- **网关只是通道**：只做认领、鉴权、配对登记、路由、在线状态和转发。手机和电脑之间的连接由两端自己端到端加密（TLS 1.3，互验公钥），网关只转发它读不懂、也改不了的数据。它**不提供任何页面或内容**：`/v1/` 以外的路径一律 404。不保存对话、记忆、文件，也不排队离线任务；手机不在线时，发送方会明确收到 `device_offline`。
- **授权的根在手机上**：新设备必须经手机确认才能配对；每条消息都由发送方签名，由接收方验签。网关本身不是最终的授权者。

> English: a self-hosted relay (one Worker + one SQLite-backed Durable Object with hibernatable WebSockets) between an ash agent phone and the user's other devices. It stores only public keys and grants — never conversations — and every state change is signed by the phone.

## 架构

```text
你的 Cloudflare 账户
  https://ash-gateway.<你的子域>.workers.dev
                │
        Worker：只放行 /v1/*，Origin 检查、请求体大小限制
                │
        GatewayHub（1 个 SQLite DO）：认领、挑战/会话、配对登记、撤销、路由、转发
                │
      ┌─────────┴─────────┐
      │ WSS               │ WSS
 ash 手机（owner）  ══ 端到端加密的 /link 通道 ══  电脑（client）
```

## 部署（首版：从 GitHub 部署，再手动接到 APK）

1. **生成认领密钥**：先准备一个随机串，例如 `openssl rand -base64 32`。之后 ash App 会提供生成入口。
2. **点上面的 Deploy to Cloudflare 按钮**，登录你自己的 Cloudflare 账户，填写 `BOOTSTRAP_SECRET`。按钮会从本仓库构建，自动创建 Worker 和 `GatewayHub` Durable Object。
   - 也可以手动部署：`npm ci && npx wrangler deploy && npx wrangler secret put BOOTSTRAP_SECRET`
   - **不用源码，从 Release 部署**（ash 手机上的 agent 就这么做）：下载[最新 Release](https://github.com/wanpengxie/ash-gateway/releases/latest) 的 `ash-gateway.mjs` 和 `wrangler.jsonc` 到同一个目录，改 `wrangler.jsonc` 里的 `name`（用自己的域名就加上 `routes`），然后 `npx wrangler deploy && npx wrangler secret put BOOTSTRAP_SECRET`。Release 由打 `v*` tag 时的 GitHub Actions 构建。
3. 打开 `https://ash-gateway.<子域>.workers.dev/v1/health`，看到 `"claimed": false, "bootstrap_configured": true` 就说明部署好了。
4. **在 ash App 里填网关地址和同一个认领密钥**。手机用自己的硬件密钥完成首次认领（HMAC 证明知道密钥 + 签名证明持有私钥）。**认领只能成功一次**，之后可以在 Cloudflare 控制台删掉这个 Secret。
5. **添加设备**：在 ash 里说「接一台电脑」。Ash 在聊天里给你一行安装命令：它从 [ash 的 GitHub 发布页](https://github.com/wanpengxie/ash/releases) 下载电脑程序并校验，带着一次性配对码和一次性密钥去配对。配对码经网关登记；密钥从不经过网关，电脑和手机第一次连接时用它互相证明，网关掉包任何一方的公钥都会被发现。

**手机丢了怎么办**：在 Cloudflare 控制台 → 这个 Worker → Settings → Variables，添加或修改变量 `RESET_EPOCH`，填一个新值（比如 `1`，下次再重置就填 `2`），保存并部署。网关会清空全部设备和授权，等待重新认领。能做这件事的只有 Cloudflare 账户的持有者，任何公网请求都触发不了重置。仓库配置开启了 `keep_vars`，之后的部署不会把这个值改回去。

### 跑在自己的服务器上

不用 Cloudflare 也行：一台有公网 IP 的 Linux 服务器（nginx + `wrangler dev`），只有 IP 没有域名也能拿证书。安装、证书、升级和回滚见 [scripts/self-host/README.md](scripts/self-host/README.md)；升级只从本仓库的 GitHub 发布页取文件，按发布的 `SHA256SUMS` 校验。

### 自定义域名

当前部署绑定了 `https://ash.onestudio.cc`，同时保留原来的 `workers.dev` 地址；两个入口连接的是同一个 Worker 和 GatewayHub，不会重新认领或清空设备。

`wrangler.jsonc` 的 `routes` 保存了这项绑定。**部署到你自己的 Cloudflare 账户时，请把该域名改成你账户中已激活域名的子域名，或删除 `routes` 只使用 `workers.dev`。** Cloudflare 会为 Custom Domain 配置 DNS 和 HTTPS 证书；不要覆盖已被其他服务使用的子域名。

绑定不会自动修改手机和电脑的网关配置；要切换入口，需把它们的网关 URL 改为新地址。域名切换后，原先缓存的 DNS 负响应可能要等缓存过期才会消失。

## 设备端

设备端程序是 [ash](https://github.com/wanpengxie/ash) 仓库里的 **ash core**（它吸收了早期的 ash-link）：

- **手机（owner）**：ash App 里的中枢负责认领、配对审批（用手机 Keystore 里的密钥签名），并经 `/link` 通道连到每台电脑。
- **电脑（client）**：ash 的电脑程序（`ash-device`），由 Ash 给的安装命令装好并配对，把本机能力借给手机上的 Agent。

没有 `expose_capability` 权限的设备收不到任何隧道流量。

## 协议

完整规范见 [docs/PROTOCOL.md](docs/PROTOCOL.md)，参考实现见 [client/client.ts](client/client.ts)。

| 接口 | 作用 |
|---|---|
| `GET /v1/health` | 部署状态：是否已认领、手机是否在线 |
| `POST /v1/bootstrap/challenge` → `POST /v1/bootstrap/claim` | 手机首次认领（一次性） |
| `POST /v1/auth/challenge` → `POST /v1/auth/session` | 已登记设备用签名换一个 15 分钟有效的会话 |
| `GET /v1/ws` | 已鉴权的 WebSocket（先鉴权，后 Upgrade） |
| `POST /v1/pair/request` / `POST /v1/pair/status` | 新设备凭一次性配对码申请配对，并查询手机的批准结果 |

## 开发

```bash
npm ci
npm test                        # 协议单元测试（含 Android DER 签名互通）
cp .dev.vars.example .dev.vars   # 填一个 BOOTSTRAP_SECRET
npm run dev                     # wrangler dev，本地 http://127.0.0.1:8787
GATEWAY_URL=http://127.0.0.1:8787 BOOTSTRAP_SECRET=... npm run e2e
```

`npm run e2e` 会同时扮演手机和电脑，覆盖认领、重放、配对、签名转发、伪造发送方、离线、撤销，以及「`/v1/` 以外一律 404」；`npm run tunnel-e2e` 用手机和电脑的测试替身测设备通道：`/link` 大消息往返、替换、只认 `/link`、无 `expose_capability` 不转发、上下线通知。它会用一把临时密钥认领网关，所以**不要对你真正要给手机用的网关跑**；要跑就用单独部署的测试实例，或者跑完后用 `RESET_EPOCH` 重置。

## 免费额度

- 必须使用 Hibernation WebSocket API：DO 空闲时休眠，只在处理事件时计时。
- 协议级 ping 由运行时自动应答，不唤醒 DO；应用层的 `"ping"` 文本也配置了自动回复 `"pong"`。
- 不使用 Alarm 或定时器，也不保持常驻连接。
- 入站 WS 消息按 20:1 折算 DO 请求数。

公网入口无法防止有人故意耗尽你账户的免费额度。网关对挑战数量、配对票据、帧大小和请求体大小做了限制，这项剩余风险在此如实说明。

## 当前不包含

- **手机直部署**：由 App 通过 OAuth 替你部署。
- **Device Link**：电脑端注册能力，由手机反向调用。
- **一个账户多台 Agent 手机**。

## 许可

MIT
