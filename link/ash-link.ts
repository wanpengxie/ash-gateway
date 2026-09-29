// ash-link: the device side of the ash gateway. Zero dependencies (Node >= 22: fetch,
// WebSocket, node:http), bundled into one file that runs on the phone's embedded Node.
//
// Role "owner" (the Agent phone):
//   - claims the gateway once (BOOTSTRAP_SECRET), then keeps an authenticated WSS open;
//   - answers tunnel streams by replaying them against the local DSH engine as if they
//     came from loopback (rewrites Host/Origin, attaches the engine's own session cookie);
//   - serves a token-protected local page to create pairing codes and approve devices.
//
//   - serves a token-protected local MCP proxy (default 127.0.0.1:3096) so the phone's DSH can
//     call tools on paired devices: /d/<device id>/<server> is tunneled to that device.
//
// Role "client" (a laptop that lends its tools to the Agent):
//   - pairs once with the one-time code from the phone (`--pair <code>`), then stays connected;
//   - answers the phone's tunnel requests with its local MCP servers (stdio servers are bridged
//     to Streamable HTTP in-process; URL servers are proxied).
//
// Usage:  node ash-link.mjs --config <file> [--pair <code>]
// owner:  { "gateway": "https://…workers.dev", "stateDir": "…", "engine": { "url": "http://127.0.0.1:3090",
//           "log": "…/dsh-web.log" }, "control": { "port": 3095 }, "mcpProxy": { "port": 3096 }, "name": "agent phone" }
//         A file `<stateDir>/bootstrap-secret` is used (then deleted) for the one-time claim.
// client: { "role": "client", "gateway": "…", "stateDir": "…", "name": "MacBook",
//           "mcp": { "files": { "command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem", "/Users/me/work"] },
//                    "web":   { "url": "http://127.0.0.1:8931/mcp" } } }

import { spawn, type ChildProcessWithoutNullStreams } from "node:child_process";
import { existsSync, readFileSync, statSync, unlinkSync, writeFileSync, openSync, readSync, closeSync, mkdirSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { join } from "node:path";
import { Connection, DeviceKey, GatewayClient, GatewayError } from "../client/client";
import { b64u, fromB64u, LIMITS, type Permission, randomToken, shortFingerprint } from "../src/protocol";

type McpServer = { command: string; args?: string[]; env?: Record<string, string>; cwd?: string } | { url: string };

interface Config {
  role?: "owner" | "client";
  gateway: string;
  stateDir: string;
  name?: string;
  // owner
  engine: { url: string; log: string };
  control?: { port?: number };
  mcpProxy?: { port?: number };
  // client
  mcp?: Record<string, McpServer>;
}

interface TunnelRequest {
  method: string;
  path: string;
  headers: [string, string][];
  body: Uint8Array[];
}

/** Stream an HTTP response back over the tunnel as http.head / http.body* / http.end. */
async function streamBack(send: (f: Record<string, unknown>) => void, sid: string, res: Response, extra: Record<string, unknown> = {}): Promise<void> {
  const headers: [string, string][] = [];
  res.headers.forEach((v, k) => {
    if (!/^(set-cookie|content-length|content-encoding|transfer-encoding|connection)$/i.test(k)) headers.push([k, v]);
  });
  send({ t: "tun", op: "http.head", sid, status: res.status, headers, ...extra });
  if (res.body) {
    let buf: Uint8Array[] = [];
    let size = 0;
    const flush = () => {
      const all = Buffer.concat(buf);
      for (let i = 0; i < all.length; i += LIMITS.tunnelChunkBytes) {
        send({ t: "tun", op: "http.body", sid, data: b64u(new Uint8Array(all.subarray(i, i + LIMITS.tunnelChunkBytes))), ...extra });
      }
      buf = [];
      size = 0;
    };
    for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
      buf.push(chunk);
      size += chunk.length;
      // SSE (MCP streaming) must not wait for a full chunk.
      if (size >= LIMITS.tunnelChunkBytes || (res.headers.get("content-type") ?? "").includes("event-stream")) flush();
    }
    if (size) flush();
  }
  send({ t: "tun", op: "http.end", sid, ...extra });
}

const log = (...a: unknown[]) => console.log(new Date().toISOString(), ...a);

// ------------------------------------------------------------------ identity

async function loadOrCreateKey(stateDir: string): Promise<DeviceKey> {
  const file = join(stateDir, "device.jwk");
  if (existsSync(file)) return DeviceKey.fromJwk(JSON.parse(readFileSync(file, "utf8")));
  const key = await DeviceKey.generate();
  writeFileSync(file, JSON.stringify(await key.exportJwk()), { mode: 0o600 });
  log("generated device key", key.id);
  return key;
}

function controlToken(stateDir: string): string {
  return secretToken(stateDir, "control-token");
}

function secretToken(stateDir: string, name: string): string {
  const file = join(stateDir, name);
  if (existsSync(file)) return readFileSync(file, "utf8").trim();
  const t = randomToken(24);
  writeFileSync(file, t, { mode: 0o600 });
  return t;
}

// ------------------------------------------------------------------ local DSH engine

/** Session cookie for the local DSH web engine, taken from the token URL it prints at startup. */
class Engine {
  private cookie: string | null = null;
  private cookieFor: string | null = null;
  readonly origin: string;

  constructor(private readonly cfg: Config["engine"]) {
    this.origin = new URL(cfg.url).origin;
  }

  private tokenUrl(): string | null {
    try {
      const size = statSync(this.cfg.log).size;
      const n = Math.min(size, 256 * 1024);
      const buf = Buffer.alloc(n);
      const fd = openSync(this.cfg.log, "r");
      readSync(fd, buf, 0, n, size - n);
      closeSync(fd);
      const esc = this.origin.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const all = [...buf.toString("utf8").matchAll(new RegExp(`${esc}/\\?token=[A-Za-z0-9_-]+`, "g"))];
      return all.length ? all[all.length - 1][0] : null;
    } catch {
      return null;
    }
  }

  async auth(force = false): Promise<string | null> {
    const url = this.tokenUrl();
    if (!url) return null;
    if (!force && this.cookie && this.cookieFor === url) return this.cookie;
    const r = await fetch(url, { redirect: "manual" });
    const set = r.headers.getSetCookie();
    if (!set.length) return null;
    this.cookie = set.map((c) => c.split(";")[0]).join("; ");
    this.cookieFor = url;
    return this.cookie;
  }

  headers(from: [string, string][], cookie: string | null): Headers {
    const h = new Headers();
    for (const [k, v] of from) {
      if (/^(host|origin|referer|cookie|sec-fetch-.*|accept-encoding)$/i.test(k)) continue;
      h.append(k, v);
    }
    if (from.some(([k]) => k.toLowerCase() === "origin")) h.set("origin", this.origin);
    if (cookie) h.set("cookie", cookie);
    return h;
  }
}

// ------------------------------------------------------------------ owner

class Owner {
  private conn: Connection | null = null;
  private readonly httpReqs = new Map<string, { method: string; path: string; headers: [string, string][]; body: Uint8Array[] }>();
  private readonly sockets = new Map<string, { ws: WebSocket; queue: (string | Uint8Array)[]; parts: string[] }>();
  readonly pending = new Map<string, { request_id: string; client_id: string; name: string; pubkey: string; fingerprint: string; at: number }>();
  /** Requests this phone sent to a device (MCP proxy), waiting for / streaming the device's answer. */
  private readonly outbound = new Map<string, { head: (h: { status: number; headers: [string, string][] }) => void; data: (b: Uint8Array) => void; end: (err?: string) => void }>();
  connected = false;

  constructor(
    readonly gw: GatewayClient,
    readonly engine: Engine,
  ) {}

  async run(): Promise<never> {
    let delay = 1000;
    for (;;) {
      try {
        const session = await this.gw.authenticate();
        const conn = await this.gw.connect(session);
        this.conn = conn;
        this.connected = true;
        delay = 1000;
        log("connected to gateway as owner", this.gw.key.id);
        conn.onUnmatched = (f) => this.onFrame(f);
        const keepalive = setInterval(() => conn.ws.readyState === WebSocket.OPEN && conn.ws.send("ping"), 30_000);
        const pend = await conn.request({ op: "pair.pending" }).catch(() => null);
        for (const r of ((pend?.requests as Record<string, string>[] | undefined) ?? [])) {
          this.pending.set(r.request_id, { request_id: r.request_id, client_id: r.client_id, name: r.name, pubkey: r.pubkey, fingerprint: await shortFingerprint(r.pubkey), at: Date.now() });
        }
        const closed = await conn.closed;
        clearInterval(keepalive);
        log("gateway connection closed", closed.code, closed.reason);
      } catch (e) {
        log("gateway connection failed:", e instanceof Error ? e.message : e);
      }
      this.connected = false;
      this.conn = null;
      for (const [, s] of this.sockets) s.ws.close();
      this.sockets.clear();
      this.httpReqs.clear();
      await sleep(delay * (0.5 + Math.random() / 2));
      delay = Math.min(delay * 2, 30_000);
    }
  }

  private send(frame: Record<string, unknown>): void {
    const c = this.conn;
    if (c && c.ws.readyState === WebSocket.OPEN) c.ws.send(JSON.stringify(frame));
  }

  private onFrame(f: Record<string, unknown>): void {
    if (f.t === "tun" && typeof f.sid === "string" && this.outbound.has(f.sid)) return this.onOutbound(f);
    if (f.t === "gw" && f.op === "pair.request") {
      shortFingerprint(String(f.pubkey)).then((fingerprint) => {
        this.pending.set(String(f.request_id), { request_id: String(f.request_id), client_id: String(f.client_id), name: String(f.name), pubkey: String(f.pubkey), fingerprint, at: Date.now() });
        log(`pairing request from "${f.name}" (${fingerprint}) — approve it on the control page`);
      });
      return;
    }
    if (f.t !== "tun") return;
    const sid = String(f.sid);
    switch (f.op) {
      case "http.req":
        this.httpReqs.set(sid, { method: String(f.method), path: String(f.path), headers: (f.headers as [string, string][]) ?? [], body: [] });
        return;
      case "http.reqbody":
        this.httpReqs.get(sid)?.body.push(fromB64u(String(f.data)));
        return;
      case "http.reqend": {
        const req = this.httpReqs.get(sid);
        this.httpReqs.delete(sid);
        if (req) this.proxyHttp(sid, req).catch((e) => this.send({ t: "tun", op: "http.error", sid, message: String(e?.message ?? e) }));
        return;
      }
      case "ws.open":
        this.openWs(sid, String(f.path));
        return;
      case "ws.msg": {
        const s = this.sockets.get(sid);
        if (!s) return;
        const part = typeof f.text === "string" ? f.text : String(f.b64 ?? "");
        s.parts.push(part);
        if (f.more === true) return;
        const whole = s.parts.join("");
        s.parts = [];
        const data = typeof f.b64 === "string" ? fromB64u(whole) : whole;
        if (s.ws.readyState === WebSocket.OPEN) s.ws.send(data);
        else s.queue.push(data);
        return;
      }
      case "ws.close": {
        const s = this.sockets.get(sid);
        this.sockets.delete(sid);
        s?.ws.close(1000);
        return;
      }
    }
  }

  private async proxyHttp(sid: string, req: TunnelRequest): Promise<void> {
    const body = req.body.length ? Buffer.concat(req.body) : undefined;
    let res: Response | null = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const cookie = await this.engine.auth(attempt > 0);
      res = await fetch(this.engine.origin + req.path, { method: req.method, headers: this.engine.headers(req.headers, cookie), body, redirect: "manual" });
      if (res.status !== 401) break;
    }
    if (!res) throw new Error("engine unreachable");
    await streamBack((f) => this.send(f), sid, res);
  }

  private openWs(sid: string, path: string): void {
    this.engine.auth().then((cookie) => {
      const url = this.engine.origin.replace(/^http/, "ws") + path;
      const ws = new WebSocket(url, { headers: { ...(cookie ? { cookie } : {}), origin: this.engine.origin } } as unknown as string[]);
      ws.binaryType = "arraybuffer";
      const entry = { ws, queue: [] as (string | Uint8Array)[], parts: [] as string[] };
      this.sockets.set(sid, entry);
      ws.addEventListener("open", () => {
        this.send({ t: "tun", op: "ws.opened", sid });
        for (const m of entry.queue) ws.send(m);
        entry.queue = [];
      });
      ws.addEventListener("message", (ev) => {
        const binary = typeof ev.data !== "string";
        const payload = binary ? b64u(new Uint8Array(ev.data as ArrayBuffer)) : (ev.data as string);
        const n = LIMITS.tunnelChunkBytes;
        if (payload.length === 0) return this.send({ t: "tun", op: "ws.msg", sid, [binary ? "b64" : "text"]: "" });
        for (let i = 0; i < payload.length; i += n) {
          this.send({ t: "tun", op: "ws.msg", sid, [binary ? "b64" : "text"]: payload.slice(i, i + n), more: i + n < payload.length });
        }
      });
      ws.addEventListener("close", (ev) => {
        if (this.sockets.get(sid)?.ws === ws) {
          this.sockets.delete(sid);
          this.send({ t: "tun", op: "ws.close", sid, code: ev.code, reason: ev.reason });
        }
      });
      ws.addEventListener("error", () => {
        if (ws.readyState !== WebSocket.OPEN) this.send({ t: "tun", op: "ws.error", sid, message: "engine websocket failed" });
      });
    });
  }

  private onOutbound(f: Record<string, unknown>): void {
    const o = this.outbound.get(String(f.sid))!;
    switch (f.op) {
      case "http.head":
        return o.head({ status: Number(f.status), headers: (f.headers as [string, string][]) ?? [] });
      case "http.body":
        return o.data(fromB64u(String(f.data)));
      case "http.end":
        this.outbound.delete(String(f.sid));
        return o.end();
      case "http.error":
        this.outbound.delete(String(f.sid));
        return o.end(String(f.message ?? "tunnel error"));
    }
  }

  /** Send one HTTP request to a paired device through the gateway; the answer streams into `res`. */
  forward(to: string, req: TunnelRequest, res: ServerResponse): void {
    if (!this.conn) {
      res.writeHead(503, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "offline", message: "not connected to the gateway" }));
      return;
    }
    const sid = randomToken(12);
    let started = false;
    const timer = setTimeout(() => this.outbound.get(sid)?.end("device did not answer in time"), 150_000);
    this.outbound.set(sid, {
      head: ({ status, headers }) => {
        started = true;
        res.writeHead(status, Object.fromEntries(headers.filter(([k]) => !/^(content-length|transfer-encoding|connection)$/i.test(k))));
      },
      data: (b) => res.write(b),
      end: (err) => {
        clearTimeout(timer);
        this.outbound.delete(sid);
        if (err && !started) {
          res.writeHead(err === "device_offline" ? 503 : 502, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: err }));
        } else res.end();
      },
    });
    this.send({ t: "tun", op: "http.req", sid, to, method: req.method, path: req.path, headers: req.headers });
    const body = req.body.length ? Buffer.concat(req.body) : null;
    if (body) {
      for (let i = 0; i < body.length; i += LIMITS.tunnelChunkBytes) {
        this.send({ t: "tun", op: "http.reqbody", sid, to, data: b64u(new Uint8Array(body.subarray(i, i + LIMITS.tunnelChunkBytes))) });
      }
    }
    this.send({ t: "tun", op: "http.reqend", sid, to });
  }

  // ---------------------------------------------------------------- owner operations (control page)

  private async grant(): Promise<number> {
    const c = this.requireConn();
    return Number((await c.request({ op: "device.list" })).grant_version) + 1;
  }

  private requireConn(): Connection {
    if (!this.conn) throw new GatewayError(503, "offline", "not connected to the gateway");
    return this.conn;
  }

  async ticket(): Promise<{ ticket: string; expires_in: number }> {
    return { ticket: await this.gw.createPairTicket(this.requireConn()), expires_in: 300 };
  }

  async approve(requestId: string, permissions: Permission[]) {
    const r = this.pending.get(requestId);
    if (!r) throw new GatewayError(404, "unknown_request", "no such pending request");
    await this.gw.approve(this.requireConn(), r, permissions, await this.grant());
    this.pending.delete(requestId);
  }

  async reject(requestId: string) {
    await this.requireConn().request({ op: "pair.reject", request_id: requestId });
    this.pending.delete(requestId);
  }

  async revoke(clientId: string) {
    await this.gw.revoke(this.requireConn(), clientId, await this.grant());
  }

  async devices() {
    return this.conn ? (await this.conn.request({ op: "device.list" })).devices : [];
  }
}

// ------------------------------------------------------------------ control page

function serveControl(owner: Owner, port: number, token: string, fingerprint: string): void {
  const send = (res: ServerResponse, status: number, body: unknown, type = "application/json") => {
    res.writeHead(status, { "content-type": `${type}; charset=utf-8`, "cache-control": "no-store" });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };
  const readBody = (req: IncomingMessage) =>
    new Promise<Record<string, unknown>>((ok) => {
      let s = "";
      req.on("data", (d) => (s += d));
      req.on("end", () => {
        try {
          ok(JSON.parse(s || "{}"));
        } catch {
          ok({});
        }
      });
    });
  createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    // Every other app on the phone can reach loopback ports: require the control token.
    const cookieOk = (req.headers.cookie ?? "").includes(`ash_link=${token}`);
    if (url.searchParams.get("t") === token) {
      res.writeHead(303, { location: "/", "set-cookie": `ash_link=${token}; Path=/; HttpOnly; SameSite=Strict` });
      return res.end();
    }
    if (!cookieOk && req.headers["x-ash-link"] !== token) return send(res, 401, "unauthorized", "text/plain");
    try {
      if (req.method === "GET" && url.pathname === "/") return send(res, 200, CONTROL_PAGE, "text/html");
      if (req.method === "GET" && url.pathname === "/api/state") {
        return send(res, 200, {
          connected: owner.connected,
          gateway: owner.gw.origin,
          owner_id: owner.gw.key.id,
          owner_fingerprint: fingerprint,
          pending: [...owner.pending.values()],
          devices: await owner.devices().catch(() => []),
        });
      }
      if (req.method !== "POST") return send(res, 404, { error: "not_found" });
      const body = await readBody(req);
      if (url.pathname === "/api/ticket") return send(res, 200, await owner.ticket());
      if (url.pathname === "/api/approve") {
        await owner.approve(String(body.request_id), (body.permissions as Permission[]) ?? ["chat"]);
        return send(res, 200, { ok: true });
      }
      if (url.pathname === "/api/reject") return send(res, 200, (await owner.reject(String(body.request_id)), { ok: true }));
      if (url.pathname === "/api/revoke") return send(res, 200, (await owner.revoke(String(body.client_id)), { ok: true }));
      send(res, 404, { error: "not_found" });
    } catch (e) {
      send(res, e instanceof GatewayError && e.status ? e.status : 500, { error: e instanceof GatewayError ? e.code : "internal", message: e instanceof Error ? e.message : String(e) });
    }
  }).listen(port, "127.0.0.1", () => log(`control page on http://127.0.0.1:${port}/?t=<control-token>`));
}

const CONTROL_PAGE = `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ash · 设备</title><style>
body{font:15px/1.6 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1d2430}main{max-width:32rem;margin:0 auto;padding:1.2rem}
section{background:#fff;border-radius:12px;padding:1rem 1.2rem;margin:1rem 0;box-shadow:0 1px 8px #0001}h2{font-size:1.05rem;margin:0 0 .5rem}
button{padding:.45rem .9rem;border:0;border-radius:7px;background:#3d63f5;color:#fff;font-size:.95rem;margin:.2rem .3rem .2rem 0}
button.gray{background:#8b95a5}code{background:#eef1f6;padding:.1rem .35rem;border-radius:5px;word-break:break-all}.muted{color:#7a8595;font-size:.85rem}
</style></head><body><main><h1>Ash · 设备</h1><div id="v">加载中…</div></main><script>
const post=(p,b)=>fetch(p,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(b||{})}).then(r=>r.json());
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let ticket=null;
async function render(){const s=await fetch("/api/state").then(r=>r.json());
let h='<section><h2>网关</h2><p>'+(s.connected?"🟢 已连接":"🔴 未连接")+' <span class="muted">'+esc(s.gateway)+'</span></p><p class="muted">手机指纹 <code>'+esc(s.owner_fingerprint)+'</code></p></section>';
h+='<section><h2>添加设备</h2><button onclick="mk()">生成配对码</button>'+(ticket?'<p>在新设备上打开 <code>'+esc(s.gateway)+'</code>，粘贴配对码（5 分钟内有效）：</p><p><code>'+esc(ticket)+'</code></p>':'')+'</section>';
h+='<section><h2>待确认</h2>'+(s.pending.length?s.pending.map(p=>'<p><b>'+esc(p.name)+'</b><br><span class="muted">设备指纹</span> <code>'+esc(p.fingerprint)+'</code><br><label><input type="checkbox" id="w_'+p.request_id+'" checked> 网页端（完整界面）</label><br><label><input type="checkbox" id="x_'+p.request_id+'"> 开放本机工具给 Agent（笔记本等）</label><br><button onclick="ok(\\''+p.request_id+'\\')">批准</button><button class="gray" onclick="no(\\''+p.request_id+'\\')">拒绝</button></p>').join(''):'<p class="muted">没有</p>')+'</section>';
h+='<section><h2>已配对</h2>'+(s.devices.length?s.devices.map(d=>'<p>'+(d.online?"🟢 ":"⚪️ ")+esc(d.name)+' <span class="muted">'+esc(d.permissions.join(", "))+(d.revoked?" · 已撤销":"")+'</span>'+(d.revoked?'':' <button class="gray" onclick="rv(\\''+d.id+'\\')">撤销</button>')+'</p>').join(''):'<p class="muted">没有</p>')+'</section>';
document.getElementById("v").innerHTML=h;}
async function mk(){const r=await post("/api/ticket");ticket=r.ticket;render();}
async function ok(id){const perms=["chat"];if(document.getElementById("w_"+id).checked)perms.push("web_ui");if(document.getElementById("x_"+id).checked)perms.push("expose_capability");await post("/api/approve",{request_id:id,permissions:perms});render();}
async function no(id){await post("/api/reject",{request_id:id});render();}
async function rv(id){if(confirm("撤销这个设备？"))await post("/api/revoke",{client_id:id});render();}
render();setInterval(render,3000);
</script></body></html>`;

// ------------------------------------------------------------------ owner: MCP proxy for DSH

/**
 * Local Streamable-HTTP endpoint for the phone's DSH `dsh-mcp-client`:
 *   http://127.0.0.1:<port>/d/<device id>/<server>   (header x-ash-link: <mcp token>)
 * Everything is forwarded unchanged to `/mcp/<server>` on that device through the gateway.
 */
function serveMcpProxy(owner: Owner, port: number, token: string): void {
  createServer((req, res) => {
    if (req.headers["x-ash-link"] !== token) {
      res.writeHead(401).end("unauthorized");
      return;
    }
    const m = /^\/d\/([A-Za-z0-9_-]{22})\/([A-Za-z0-9_-]{1,32})(\/.*)?$/.exec(new URL(req.url ?? "/", "http://x").pathname);
    if (!m) {
      res.writeHead(404).end("use /d/<device id>/<server>");
      return;
    }
    const chunks: Buffer[] = [];
    req.on("data", (c: Buffer) => chunks.push(c));
    req.on("end", () => {
      const headers: [string, string][] = [];
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === "string" && !/^(host|connection|content-length|x-ash-link|transfer-encoding)$/i.test(k)) headers.push([k, v]);
      }
      owner.forward(m[1], { method: req.method ?? "GET", path: `/mcp/${m[2]}${m[3] ?? ""}`, headers, body: chunks.length ? [Buffer.concat(chunks)] : [] }, res);
    });
  }).listen(port, "127.0.0.1", () => log(`MCP proxy for DSH on http://127.0.0.1:${port}/d/<device>/<server>`));
}

// ------------------------------------------------------------------ client: local MCP servers

/**
 * Minimal Streamable-HTTP front for a stdio MCP server: each POST carries one JSON-RPC
 * message (or a batch); requests are answered with their responses as JSON, notifications
 * with 202. Server-initiated streams (GET) are not offered (405), which the spec allows.
 */
class StdioMcp {
  private child: ChildProcessWithoutNullStreams | null = null;
  private readonly waiting = new Map<string, (msg: unknown) => void>();
  private buf = "";

  constructor(
    readonly name: string,
    private readonly spec: { command: string; args?: string[]; env?: Record<string, string>; cwd?: string },
  ) {}

  private ensure(): ChildProcessWithoutNullStreams {
    if (this.child && this.child.exitCode === null) return this.child;
    const child = spawn(this.spec.command, this.spec.args ?? [], { cwd: this.spec.cwd, env: { ...process.env, ...this.spec.env }, stdio: ["pipe", "pipe", "pipe"] });
    child.stderr.on("data", (d) => log(`[mcp ${this.name}]`, String(d).trim()));
    child.stdout.on("data", (d) => {
      this.buf += String(d);
      let nl: number;
      while ((nl = this.buf.indexOf("\n")) >= 0) {
        const line = this.buf.slice(0, nl).trim();
        this.buf = this.buf.slice(nl + 1);
        if (!line) continue;
        try {
          const msg = JSON.parse(line) as { id?: unknown; method?: string };
          const key = JSON.stringify(msg.id);
          if (msg.id !== undefined && msg.method === undefined && this.waiting.has(key)) {
            this.waiting.get(key)!(msg);
            this.waiting.delete(key);
          }
        } catch {
          log(`[mcp ${this.name}] non-JSON output:`, line.slice(0, 200));
        }
      }
    });
    child.on("exit", (code) => {
      log(`[mcp ${this.name}] exited`, code);
      for (const [, w] of this.waiting) w({ jsonrpc: "2.0", id: null, error: { code: -32000, message: "MCP server exited" } });
      this.waiting.clear();
    });
    this.child = child;
    log(`[mcp ${this.name}] started: ${this.spec.command} ${(this.spec.args ?? []).join(" ")}`);
    return child;
  }

  async handle(method: string, bodyText: string): Promise<Response> {
    if (method === "GET") return new Response(null, { status: 405, headers: { allow: "POST, DELETE" } });
    if (method === "DELETE") return new Response(null, { status: 200 });
    if (method !== "POST") return new Response(null, { status: 405 });
    let parsed: unknown;
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }, { status: 400 });
    }
    const msgs = (Array.isArray(parsed) ? parsed : [parsed]) as { id?: unknown; method?: string }[];
    const child = this.ensure();
    const answers = msgs
      .filter((m) => m.method !== undefined && m.id !== undefined)
      .map(
        (m) =>
          new Promise<unknown>((resolve) => {
            const key = JSON.stringify(m.id);
            const t = setTimeout(() => {
              this.waiting.delete(key);
              resolve({ jsonrpc: "2.0", id: m.id, error: { code: -32001, message: "MCP server timed out" } });
            }, 120_000);
            this.waiting.set(key, (msg) => (clearTimeout(t), resolve(msg)));
          }),
      );
    for (const m of msgs) child.stdin.write(JSON.stringify(m) + "\n");
    if (answers.length === 0) return new Response(null, { status: 202 });
    const out = await Promise.all(answers);
    return Response.json(Array.isArray(parsed) ? out : out[0]);
  }
}

class Device {
  private conn: Connection | null = null;
  private readonly reqs = new Map<string, TunnelRequest>();
  private readonly stdio = new Map<string, StdioMcp>();

  constructor(
    readonly gw: GatewayClient,
    private readonly servers: Record<string, McpServer>,
  ) {
    for (const [name, spec] of Object.entries(servers)) if ("command" in spec) this.stdio.set(name, new StdioMcp(name, spec));
  }

  async run(): Promise<never> {
    let delay = 1000;
    for (;;) {
      try {
        const conn = await this.gw.connect(await this.gw.authenticate());
        this.conn = conn;
        delay = 1000;
        log(`connected to gateway as device ${this.gw.key.id}; serving MCP: ${Object.keys(this.servers).join(", ") || "(none)"}`);
        conn.onUnmatched = (f) => this.onFrame(f);
        const keepalive = setInterval(() => conn.ws.readyState === WebSocket.OPEN && conn.ws.send("ping"), 30_000);
        const closed = await conn.closed;
        clearInterval(keepalive);
        log("gateway connection closed", closed.code, closed.reason);
        if (closed.code === 4003) throw new Error("this device was revoked by the phone");
      } catch (e) {
        log("gateway connection failed:", e instanceof Error ? e.message : e);
        if (e instanceof Error && /revoked/.test(e.message)) process.exit(2);
      }
      this.conn = null;
      this.reqs.clear();
      await sleep(delay * (0.5 + Math.random() / 2));
      delay = Math.min(delay * 2, 30_000);
    }
  }

  private send(f: Record<string, unknown>): void {
    const c = this.conn;
    if (c && c.ws.readyState === WebSocket.OPEN) c.ws.send(JSON.stringify(f));
  }

  private onFrame(f: Record<string, unknown>): void {
    if (f.t !== "tun") return;
    const sid = String(f.sid);
    if (f.op === "http.req") this.reqs.set(sid, { method: String(f.method), path: String(f.path), headers: (f.headers as [string, string][]) ?? [], body: [] });
    else if (f.op === "http.reqbody") this.reqs.get(sid)?.body.push(fromB64u(String(f.data)));
    else if (f.op === "http.reqend") {
      const req = this.reqs.get(sid);
      this.reqs.delete(sid);
      if (req) this.serve(sid, req).catch((e) => this.send({ t: "tun", op: "http.error", sid, message: String(e?.message ?? e) }));
    }
  }

  private async serve(sid: string, req: TunnelRequest): Promise<void> {
    const m = /^\/mcp\/([A-Za-z0-9_-]{1,32})(\/.*)?$/.exec(req.path.split("?")[0]);
    const spec = m ? this.servers[m[1]] : undefined;
    let res: Response;
    if (!m || !spec) res = Response.json({ error: "unknown_server", servers: Object.keys(this.servers) }, { status: 404 });
    else if ("url" in spec) {
      const headers = new Headers();
      for (const [k, v] of req.headers) if (!/^(host|origin|cookie)$/i.test(k)) headers.append(k, v);
      res = await fetch(spec.url + (m[2] ?? ""), { method: req.method, headers, body: req.body.length ? Buffer.concat(req.body) : undefined });
    } else res = await this.stdio.get(m[1])!.handle(req.method, Buffer.concat(req.body).toString("utf8"));
    await streamBack((f) => this.send(f), sid, res);
  }
}

// ------------------------------------------------------------------ main

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function main(): Promise<void> {
  const arg = (flag: string) => {
    const i = process.argv.indexOf(flag);
    return i >= 0 ? process.argv[i + 1] : undefined;
  };
  const cfgPath = arg("--config");
  if (!cfgPath) throw new Error("usage: ash-link --config <file> [--pair <code>]");
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8")) as Config;
  mkdirSync(cfg.stateDir, { recursive: true, mode: 0o700 });
  const key = await loadOrCreateKey(cfg.stateDir);
  const gw = new GatewayClient(cfg.gateway, key);
  const fingerprint = await shortFingerprint(key.publicKey);

  if (cfg.role === "client") {
    const pairedFile = join(cfg.stateDir, "paired.json");
    if (!existsSync(pairedFile)) {
      const code = arg("--pair");
      if (!code) throw new Error("not paired yet: run once with --pair <code from the phone>");
      const pr = await gw.requestPairing(code, cfg.name ?? "laptop");
      log(`pairing requested. Confirm on the phone: this device ${fingerprint}, phone ${pr.owner_fingerprint}`);
      const grant = await gw.waitForApproval(pr.request_id, pr.owner_key, 10 * 60_000);
      writeFileSync(pairedFile, JSON.stringify({ owner_key: pr.owner_key, owner_id: pr.owner_id, ...grant }), { mode: 0o600 });
      log("paired with permissions", grant.permissions.join(", "));
      if (!grant.permissions.includes("expose_capability")) log("note: the phone did not grant expose_capability, so it cannot call this device's tools");
    }
    await new Device(gw, cfg.mcp ?? {}).run();
    return;
  }

  // One-time claim, retried until the gateway answers.
  for (;;) {
    try {
      const h = await gw.health();
      if (h.claimed) {
        if (h.owner_id !== key.id) throw new Error(`gateway is owned by another device (${String(h.owner_id)}); reset it from the Cloudflare account`);
        break;
      }
      const secretFile = join(cfg.stateDir, "bootstrap-secret");
      if (!existsSync(secretFile)) throw new Error(`gateway is unclaimed: put its BOOTSTRAP_SECRET into ${secretFile}`);
      const r = await gw.claim(readFileSync(secretFile, "utf8").trim(), cfg.name ?? "agent phone");
      unlinkSync(secretFile);
      log("claimed the gateway as owner", r.owner_id, r.fingerprint);
      break;
    } catch (e) {
      log("claim/health:", e instanceof Error ? e.message : e);
      await sleep(15_000);
    }
  }

  const owner = new Owner(gw, new Engine(cfg.engine));
  serveControl(owner, cfg.control?.port ?? 3095, controlToken(cfg.stateDir), fingerprint);
  serveMcpProxy(owner, cfg.mcpProxy?.port ?? 3096, secretToken(cfg.stateDir, "mcp-token"));
  await owner.run();
}

main().catch((e) => {
  console.error(e instanceof Error ? e.stack : e);
  process.exit(1);
});
