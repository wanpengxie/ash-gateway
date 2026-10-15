# 在自己的服务器上跑中转站

中转站也可以不放在 Cloudflare，而是跑在你自己的一台 Linux 服务器上：用 `wrangler dev` 起 workerd，前面放 nginx 做 TLS。只有一个公网 IP、没有域名也行。

这里的文件：

| 文件 | 放到哪 | 作用 |
|---|---|---|
| `ash-relay.service` | `/etc/systemd/system/` | 中转站服务（workerd，只听 127.0.0.1:8787） |
| `ash-relay.default` | `/etc/default/ash-relay` | `ASH_RELAY_PUBLIC`：客户端连的地址（IP 或主机名） |
| `nginx-ash-relay.conf` | `/etc/nginx/conf.d/` | 443：TLS，只放行 `/v1/`，别的路径一律 404 |
| `nginx-ash-port80.conf` | `/etc/nginx/conf.d/` | 80：只给证书验证用（certbot webroot） |
| `certbot-ash.service` / `.timer` | `/etc/systemd/system/` | 证书自动续期，每天两次 |
| `upgrade.sh` | `/opt/ash-relay/bin/upgrade.sh` | 升级到某个发布版本，失败自动回滚 |

## 目录

```
/opt/ash-relay/
  node_modules/            wrangler（装一次：npm install --prefix /opt/ash-relay wrangler@4）
  .dev.vars                BOOTSTRAP_SECRET=…（0600；认领密钥，不要放进任何仓库）
  releases/<版本>/          每个发布版本：ash-gateway.mjs、wrangler.jsonc、wrangler.local.jsonc、.dev.vars 的链接
  current -> releases/<版本>
  bin/upgrade.sh           升级脚本（每次升级后换成新版本自带的那份）
/var/lib/ash-relay/        中转站的状态（主人、设备、授权）。不在版本目录里，升级不动它
```

`wrangler.local.jsonc` 是发布版本的 `wrangler.jsonc` 去掉 `routes`、`workers_dev: false`：带自定义域名时 `wrangler dev` 会改写 Host，认领和登录的签名就对不上（`bad_mac`）。Worker 的名字固定是 `ash-gateway`，状态按这个名字存。

## 第一次安装

1. 装 Node 22、nginx、curl。服务器的安全组（防火墙）入方向开 TCP 80 和 443。
2. 装 wrangler：`mkdir -p /opt/ash-relay && npm install --prefix /opt/ash-relay wrangler@4`。
3. 认领密钥：`printf 'BOOTSTRAP_SECRET=%s\n' "$(openssl rand -base64 32)" > /opt/ash-relay/.dev.vars && chmod 600 /opt/ash-relay/.dev.vars`。同一个值在 Ash 里认领中转站时用一次（Ash 会让你把它存进保险箱）。
4. 证书（见下一节），然后放 nginx 的两份配置，把里面的 `203.0.113.7` 换成你的地址，`nginx -t && systemctl reload nginx`。
5. 服务：`/etc/default/ash-relay` 写 `ASH_RELAY_PUBLIC=<你的地址>`，`ash-relay.service` 放进 `/etc/systemd/system/`，`systemctl daemon-reload && systemctl enable ash-relay`。
6. 装第一个版本：`install -D -m 755 upgrade.sh /opt/ash-relay/bin/upgrade.sh && /opt/ash-relay/bin/upgrade.sh 0.7.1`（换成最新的版本号）。看到 `relay … is up` 就好了；`curl https://<你的地址>/v1/health` 应该是 `"claimed": false`。
7. 在 Ash 里用这个地址（`https://<你的地址>`）认领中转站。

已经在用源码目录跑（`/opt/ash-relay` 是仓库的 clone、`WorkingDirectory=/opt/ash-relay`）的：保留 `node_modules` 和 `.dev.vars`，换上这里的 `ash-relay.service` 和 `/etc/default/ash-relay`，`systemctl daemon-reload`，再跑第 6 步。状态在 `/var/lib/ash-relay`，不受影响。这一次没有可回滚的旧版本：失败了就把旧的服务文件换回去。

## 只用 IP 时怎么拿证书

Let's Encrypt 发 IP 地址证书（只能用 HTTP-01 或 TLS-ALPN-01 验证，有效期约 6 天，要用 `shortlived` 档）。需要较新的 certbot（发行版自带的往往太老，不认 `--ip-address` 和档位），装在一个 venv 里：

```sh
python3 -m venv /opt/certbot
/opt/certbot/bin/pip install certbot
mkdir -p /var/www/ash
# 先放好 nginx-ash-port80.conf 并 reload：80 端口要能取到 /.well-known/acme-challenge/
/opt/certbot/bin/certbot certonly --non-interactive --agree-tos --register-unsafely-without-email \
  --webroot -w /var/www/ash --ip-address <你的 IP> --preferred-profile shortlived
```

证书在 `/etc/letsencrypt/live/<你的 IP>/{fullchain,privkey}.pem`。有效期很短，必须自动续期：放好 `certbot-ash.service` 和 `certbot-ash.timer`，`systemctl enable --now certbot-ash.timer`。续上后会 `systemctl reload nginx`。

有域名的话，直接给域名签普通证书即可（`--domains`），`ASH_RELAY_PUBLIC` 和 nginx 里的地址都写域名。

## 升级

```sh
/opt/ash-relay/bin/upgrade.sh <版本>
```

它只从 GitHub 发布页（`wanpengxie/ash-gateway` 的 `v<版本>`）下载 `ash-gateway.mjs`、`wrangler.jsonc` 和 `upgrade.sh`，每一个都按同一发布的 `SHA256SUMS` 校验，对不上就停下、什么都不改。然后：

1. 放进 `releases/<版本>`，生成 `wrangler.local.jsonc`，链上 `.dev.vars`；
2. 把 `current` 原子地切过去，`systemctl restart ash-relay`；
3. 等 `/v1/health` 报出这个版本（最多 90 秒）。等到了：换上新版本自带的 `upgrade.sh`，只留最近三个版本；
4. 等不到：切回原来的版本、重启，退出码 1，删掉失败的版本目录。

已经是这个版本就什么都不做（`ASH_RELAY_FORCE=1` 可以重装）。连不上 GitHub 是这台机器的网络问题：设 `HTTPS_PROXY`（curl 认它）后再跑。

**Ash 自己升级**：这台服务器接成 Ash 的电脑并当作 body 的话，Ash 在它上面执行 `/opt/ash-relay/bin/upgrade.sh <版本>`（以 root），看输出判断成没成功，不用主人登录服务器。
