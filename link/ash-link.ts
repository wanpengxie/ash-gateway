// ash-link: the device side of the ash gateway. Zero dependencies (Node >= 22: fetch,
// WebSocket, node:http), bundled into one file that runs on the phone's embedded Node.
//
// Role "owner" (the Agent phone):
//   - claims the gateway once (BOOTSTRAP_SECRET), then keeps an authenticated WSS open;
//   - answers tunnel streams by replaying them against the local DSH engine as if they
//     came from loopback (rewrites Host/Origin, attaches the engine's own session cookie);
//   - serves a token-protected local page to create pairing codes and approve devices.
//
// Usage:  node ash-link.mjs --config <file>
// config: { "gateway": "https://…workers.dev", "stateDir": "…", "engine": { "url": "http://127.0.0.1:3090",
//           "log": "…/dsh-web.log" }, "control": { "port": 3095 }, "name": "agent phone" }
// A file `<stateDir>/bootstrap-secret` is used (then deleted) for the one-time claim.

import { existsSync, readFileSync, statSync, unlinkSync, writeFileSync, openSync, readSync, closeSync, mkdirSync } from "node:fs";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { join } from "node:path";
import { Connection, DeviceKey, GatewayClient, GatewayError } from "../client/client";
import { b64u, fromB64u, LIMITS, type Permission, randomToken, shortFingerprint } from "../src/protocol";

interface Config {
  gateway: string;
  stateDir: string;
  engine: { url: string; log: string };
  control?: { port?: number };
  name?: string;
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
  const file = join(stateDir, "control-token");
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

  private async proxyHttp(sid: string, req: { method: string; path: string; headers: [string, string][]; body: Uint8Array[] }): Promise<void> {
    const body = req.body.length ? Buffer.concat(req.body) : undefined;
    let res: Response | null = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const cookie = await this.engine.auth(attempt > 0);
      res = await fetch(this.engine.origin + req.path, { method: req.method, headers: this.engine.headers(req.headers, cookie), body, redirect: "manual" });
      if (res.status !== 401) break;
    }
    if (!res) throw new Error("engine unreachable");
    const headers: [string, string][] = [];
    res.headers.forEach((v, k) => {
      if (!/^(set-cookie|content-length|content-encoding|transfer-encoding|connection)$/i.test(k)) headers.push([k, v]);
    });
    this.send({ t: "tun", op: "http.head", sid, status: res.status, headers });
    if (res.body) {
      let buf: Uint8Array[] = [];
      let size = 0;
      for await (const chunk of res.body as unknown as AsyncIterable<Uint8Array>) {
        buf.push(chunk);
        size += chunk.length;
        if (size >= LIMITS.tunnelChunkBytes) {
          this.flushBody(sid, buf);
          buf = [];
          size = 0;
        }
      }
      if (size) this.flushBody(sid, buf);
    }
    this.send({ t: "tun", op: "http.end", sid });
  }

  private flushBody(sid: string, parts: Uint8Array[]): void {
    const all = Buffer.concat(parts);
    for (let i = 0; i < all.length; i += LIMITS.tunnelChunkBytes) {
      this.send({ t: "tun", op: "http.body", sid, data: b64u(new Uint8Array(all.subarray(i, i + LIMITS.tunnelChunkBytes))) });
    }
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
h+='<section><h2>待确认</h2>'+(s.pending.length?s.pending.map(p=>'<p><b>'+esc(p.name)+'</b><br><span class="muted">设备指纹</span> <code>'+esc(p.fingerprint)+'</code><br><label><input type="checkbox" id="w_'+p.request_id+'" checked> 网页端（完整界面）</label><br><button onclick="ok(\\''+p.request_id+'\\')">批准</button><button class="gray" onclick="no(\\''+p.request_id+'\\')">拒绝</button></p>').join(''):'<p class="muted">没有</p>')+'</section>';
h+='<section><h2>已配对</h2>'+(s.devices.length?s.devices.map(d=>'<p>'+(d.online?"🟢 ":"⚪️ ")+esc(d.name)+' <span class="muted">'+esc(d.permissions.join(", "))+(d.revoked?" · 已撤销":"")+'</span>'+(d.revoked?'':' <button class="gray" onclick="rv(\\''+d.id+'\\')">撤销</button>')+'</p>').join(''):'<p class="muted">没有</p>')+'</section>';
document.getElementById("v").innerHTML=h;}
async function mk(){const r=await post("/api/ticket");ticket=r.ticket;render();}
async function ok(id){const perms=["chat"];if(document.getElementById("w_"+id).checked)perms.push("web_ui");await post("/api/approve",{request_id:id,permissions:perms});render();}
async function no(id){await post("/api/reject",{request_id:id});render();}
async function rv(id){if(confirm("撤销这个设备？"))await post("/api/revoke",{client_id:id});render();}
render();setInterval(render,3000);
</script></body></html>`;

// ------------------------------------------------------------------ main

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

async function main(): Promise<void> {
  const i = process.argv.indexOf("--config");
  if (i < 0) throw new Error("usage: ash-link --config <file>");
  const cfg = JSON.parse(readFileSync(process.argv[i + 1], "utf8")) as Config;
  mkdirSync(cfg.stateDir, { recursive: true, mode: 0o700 });
  const key = await loadOrCreateKey(cfg.stateDir);
  const gw = new GatewayClient(cfg.gateway, key);
  const fingerprint = await shortFingerprint(key.publicKey);

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
  await owner.run();
}

main().catch((e) => {
  console.error(e instanceof Error ? e.stack : e);
  process.exit(1);
});
