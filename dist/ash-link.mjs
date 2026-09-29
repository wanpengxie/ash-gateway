// link/ash-link.ts
import { spawn } from "node:child_process";
import { existsSync, readFileSync, statSync, unlinkSync, writeFileSync, openSync, readSync, closeSync, mkdirSync } from "node:fs";
import { createServer } from "node:http";
import { join } from "node:path";

// src/protocol.ts
var PROTOCOL = "ash-gw/1";
var LIMITS = {
  /** HTTP request body. */
  maxBodyBytes: 16 * 1024,
  /** One WebSocket frame (envelope or control). */
  maxFrameBytes: 64 * 1024,
  /** One tunnel frame from the phone (Cloudflare's WebSocket message cap is 1 MiB). */
  maxTunnelFrameBytes: 1024 * 1024 - 1024,
  challengeTtlMs: 6e4,
  sessionTtlMs: 15 * 6e4,
  pairTicketMaxTtlMs: 5 * 6e4,
  pairRequestTtlMs: 10 * 6e4,
  pairTicketMaxAttempts: 5,
  /** Live (unexpired, unused) challenges kept at once; beyond this the gateway refuses new ones. */
  maxLiveChallenges: 256,
  maxDeviceNameLength: 64,
  maxClients: 32,
  /** Browser sessions (devices holding `web_ui`) last a working day; everything else stays short. */
  browserSessionTtlMs: 12 * 60 * 6e4,
  /** Request body accepted for tunneled web requests (uploads go through here). */
  webMaxBodyBytes: 8 * 1024 * 1024,
  /** Raw bytes per tunnel data frame (base64 keeps each frame well under the 1 MiB WebSocket cap). */
  tunnelChunkBytes: 256 * 1024,
  /** How long the gateway waits for the phone to start answering a tunneled request. */
  tunnelHeadTimeoutMs: 3e4
};
function signingInput(purpose, fields) {
  for (const f of [purpose, ...fields]) {
    if (typeof f !== "string" || f.includes("\n") || f.includes("\r")) {
      throw new ProtocolError("bad_field", "signed fields must be strings without line breaks");
    }
  }
  return new TextEncoder().encode([PROTOCOL, purpose, ...fields].join("\n"));
}
var ctx = {
  bootstrapClaim: (origin, nonce, ownerKey) => signingInput("bootstrap-claim", [origin, nonce, ownerKey]),
  auth: (origin, deviceId, nonce) => signingInput("auth", [origin, deviceId, nonce]),
  pairApprove: (origin, requestId, clientId, clientKey, permissions, grantVersion) => signingInput("pair-approve", [
    origin,
    requestId,
    clientId,
    clientKey,
    [...permissions].sort().join(","),
    String(grantVersion)
  ]),
  revoke: (origin, clientId, grantVersion) => signingInput("revoke", [origin, clientId, String(grantVersion)])
};
async function envelopeSigningInput(e) {
  const payloadHash = b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(e.payload))));
  return signingInput("msg", [
    String(e.v),
    e.type,
    e.message_id,
    e.from,
    e.to,
    String(e.issued_at),
    String(e.expires_at),
    e.reply_to ?? "",
    payloadHash
  ]);
}
var ProtocolError = class extends Error {
  constructor(code, message, status = 400) {
    super(message);
    this.code = code;
    this.status = status;
  }
  code;
  status;
};
function utf8(s) {
  return new TextEncoder().encode(s);
}
function b64u(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function fromB64u(s) {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new ProtocolError("bad_encoding", "expected base64url");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - s.length % 4);
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
function randomToken(bytes = 32) {
  return b64u(crypto.getRandomValues(new Uint8Array(bytes)));
}
async function sha256b64u(s) {
  return b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(s))));
}
async function deviceIdForKey(spkiB64u) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", fromB64u(spkiB64u)));
  return b64u(digest).slice(0, 22);
}
async function shortFingerprint(spkiB64u) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", fromB64u(spkiB64u)));
  const hex = [...digest.slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{4}/g).join("-").toUpperCase();
}
async function importPublicKey(spkiB64u) {
  try {
    return await crypto.subtle.importKey(
      "spki",
      fromB64u(spkiB64u),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
  } catch {
    throw new ProtocolError("bad_key", "public key must be a P-256 SPKI in base64url");
  }
}
async function verifySignature(spkiB64u, sigB64u, data) {
  const key = await importPublicKey(spkiB64u);
  let sig;
  try {
    sig = fromB64u(sigB64u);
  } catch {
    return false;
  }
  if (sig.length !== 64) {
    const raw = derToRaw(sig);
    if (!raw) return false;
    sig = raw;
  }
  return crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, sig, data);
}
function derToRaw(der) {
  let i = 0;
  if (der[i++] !== 48) return null;
  let len = der[i++];
  if (len & 128) {
    const n = len & 127;
    if (n !== 1) return null;
    len = der[i++];
  }
  if (len !== der.length - i) return null;
  const out = new Uint8Array(64);
  for (let part = 0; part < 2; part++) {
    if (der[i++] !== 2) return null;
    let n = der[i++];
    if (n > 33 || i + n > der.length) return null;
    let v = der.slice(i, i + n);
    i += n;
    while (v.length > 32 && v[0] === 0) v = v.slice(1);
    if (v.length > 32) return null;
    out.set(v, part * 32 + (32 - v.length));
  }
  return i === der.length ? out : null;
}
async function hmacSha256(secret, data) {
  const key = await crypto.subtle.importKey("raw", utf8(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(new Uint8Array(await crypto.subtle.sign("HMAC", key, data)));
}

// client/client.ts
var DeviceKey = class _DeviceKey {
  constructor(privateKey, publicKey, id) {
    this.privateKey = privateKey;
    this.publicKey = publicKey;
    this.id = id;
  }
  privateKey;
  publicKey;
  id;
  static async generate() {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    return _DeviceKey.fromPair(pair);
  }
  /** Test helper: persist a key as JWK (a real phone keeps it in the Android Keystore instead). */
  async exportJwk() {
    return await crypto.subtle.exportKey("jwk", this.privateKey);
  }
  static async fromJwk(jwk) {
    const privateKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    const { d: _d, ...pub } = jwk;
    const publicKey = await crypto.subtle.importKey("jwk", { ...pub, key_ops: ["verify"] }, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    return _DeviceKey.fromPair({ privateKey, publicKey });
  }
  static async fromPair(pair) {
    const spki = b64u(new Uint8Array(await crypto.subtle.exportKey("spki", pair.publicKey)));
    return new _DeviceKey(pair.privateKey, spki, await deviceIdForKey(spki));
  }
  async sign(data) {
    return b64u(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.privateKey, data)));
  }
};
var GatewayError = class extends Error {
  constructor(status, code, message) {
    super(`${status} ${code}: ${message}`);
    this.status = status;
    this.code = code;
  }
  status;
  code;
};
var GatewayClient = class {
  constructor(baseUrl, key) {
    this.baseUrl = baseUrl;
    this.key = key;
    this.origin = new URL(baseUrl).origin;
  }
  baseUrl;
  key;
  origin;
  async health() {
    return this.call("GET", "/v1/health");
  }
  /** Owner only, once per deployment: prove knowledge of BOOTSTRAP_SECRET and possession of the key. */
  async claim(bootstrapSecret, name = "agent phone") {
    const { nonce } = await this.call("POST", "/v1/bootstrap/challenge", {});
    const data = ctx.bootstrapClaim(this.origin, nonce, this.key.publicKey);
    return this.call("POST", "/v1/bootstrap/claim", {
      owner_key: this.key.publicKey,
      nonce,
      mac: await hmacSha256(bootstrapSecret, data),
      sig: await this.key.sign(data),
      name
    });
  }
  async authenticate() {
    const { nonce } = await this.call("POST", "/v1/auth/challenge", { device_id: this.key.id });
    return this.call("POST", "/v1/auth/session", {
      device_id: this.key.id,
      nonce,
      sig: await this.key.sign(ctx.auth(this.origin, this.key.id, nonce))
    });
  }
  /** New client: submit the ticket scanned from the phone and wait for the owner to decide. */
  async requestPairing(ticket, name) {
    return this.call("POST", "/v1/pair/request", { ticket, pubkey: this.key.publicKey, name });
  }
  async pairingStatus(requestId) {
    return this.call("POST", "/v1/pair/status", { request_id: requestId });
  }
  /**
   * Poll until the owner approves or rejects. On approval the owner's signature is
   * checked against the owner key pinned from the QR code — a forged gateway cannot
   * hand out approvals.
   */
  async waitForApproval(requestId, pinnedOwnerKey, timeoutMs = 6e4) {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const s = await this.pairingStatus(requestId);
      if (s.status === "rejected") throw new GatewayError(403, "pair_rejected", "owner rejected the pairing");
      if (s.status === "approved") {
        if (s.owner_key !== pinnedOwnerKey) throw new GatewayError(0, "owner_mismatch", "gateway reports a different owner key");
        const permissions = s.permissions;
        const grant_version = s.grant_version;
        const data = ctx.pairApprove(this.origin, requestId, this.key.id, this.key.publicKey, permissions, grant_version);
        if (!await verifySignature(pinnedOwnerKey, s.approval_sig, data)) {
          throw new GatewayError(0, "bad_approval", "approval is not signed by the pinned owner");
        }
        return { permissions, grant_version };
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new GatewayError(0, "timeout", "pairing not decided in time");
  }
  async connect(session) {
    const wsUrl = this.baseUrl.replace(/^http/, "ws").replace(/\/$/, "") + "/v1/ws";
    const ws = new WebSocket(wsUrl, ["ash.v1", `ash.bearer.${session.token}`]);
    const conn = new Connection(ws);
    await conn.opened;
    return conn;
  }
  // ---------------------------------------------------------------- owner ops
  /** Returns the ticket to put in the QR code; the gateway only ever sees its hash. */
  async createPairTicket(conn, ttlMs = 5 * 6e4 - 1e3) {
    const ticket = randomToken(24);
    await conn.request({ op: "pair.ticket", ticket_hash: await sha256b64u(ticket), expires_at: Date.now() + ttlMs });
    return ticket;
  }
  async approve(conn, req, permissions, grantVersion) {
    const sig = await this.key.sign(ctx.pairApprove(this.origin, req.request_id, req.client_id, req.pubkey, permissions, grantVersion));
    return conn.request({ op: "pair.approve", request_id: req.request_id, permissions, grant_version: grantVersion, sig });
  }
  async revoke(conn, clientId, grantVersion) {
    const sig = await this.key.sign(ctx.revoke(this.origin, clientId, grantVersion));
    return conn.request({ op: "device.revoke", client_id: clientId, grant_version: grantVersion, sig });
  }
  // ---------------------------------------------------------------- envelopes
  async envelope(type, to, payload, opts = {}) {
    const now = Date.now();
    const unsigned = {
      v: 1,
      type,
      message_id: opts.messageId ?? randomToken(12),
      from: this.key.id,
      to,
      issued_at: now,
      expires_at: now + (opts.ttlMs ?? 6e4),
      reply_to: opts.replyTo ?? null,
      payload: JSON.stringify(payload)
    };
    return { ...unsigned, sig: await this.key.sign(await envelopeSigningInput(unsigned)) };
  }
  static async verifyEnvelope(e, senderKey) {
    const { sig, ...unsigned } = e;
    return verifySignature(senderKey, sig, await envelopeSigningInput(unsigned));
  }
  // ---------------------------------------------------------------- http
  async call(method, path, body) {
    const res = await fetch(this.baseUrl.replace(/\/$/, "") + path, {
      method,
      headers: body === void 0 ? {} : { "content-type": "application/json" },
      body: body === void 0 ? void 0 : JSON.stringify(body)
    });
    const text = await res.text();
    let data = {};
    try {
      data = JSON.parse(text);
    } catch {
    }
    if (!res.ok) throw new GatewayError(res.status, String(data.error ?? "http_error"), String(data.message ?? text.slice(0, 200)));
    return data;
  }
};
var Connection = class {
  constructor(ws) {
    this.ws = ws;
    this.opened = new Promise((resolve, reject) => {
      ws.addEventListener("open", () => resolve(), { once: true });
      ws.addEventListener("error", () => reject(new GatewayError(0, "ws_error", "websocket failed to open")), { once: true });
    });
    this.closed = new Promise((resolve) => {
      ws.addEventListener("close", (ev) => resolve({ code: ev.code, reason: ev.reason }), { once: true });
    });
    ws.addEventListener("message", (ev) => {
      const text = String(ev.data);
      if (text === "pong") return;
      let frame;
      try {
        frame = JSON.parse(text);
      } catch {
        return;
      }
      const i = this.waiters.findIndex((w) => w.pred(frame));
      if (i >= 0) this.waiters.splice(i, 1)[0].resolve(frame);
      else if (this.onUnmatched) this.onUnmatched(frame);
      else this.frames.push(frame);
    });
  }
  ws;
  opened;
  closed;
  frames = [];
  waiters = [];
  seq = 0;
  /** Long-lived connections: frames no waiter wants go here instead of piling up in the buffer. */
  onUnmatched = null;
  send(frame) {
    this.ws.send(typeof frame === "string" ? frame : JSON.stringify(frame));
  }
  next(pred, timeoutMs = 1e4) {
    const i = this.frames.findIndex(pred);
    if (i >= 0) return Promise.resolve(this.frames.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      const w = { pred, resolve: (f) => (clearTimeout(timer), resolve(f)) };
      const timer = setTimeout(() => {
        this.waiters.splice(this.waiters.indexOf(w), 1);
        reject(new GatewayError(0, "timeout", "no matching frame"));
      }, timeoutMs);
      this.waiters.push(w);
    });
  }
  /** Send a gateway control op and wait for its ".ok" (or error) answer. */
  async request(frame) {
    const id = `r${++this.seq}`;
    this.send({ t: "gw", id, ...frame });
    const answer = await this.next((f) => f.t === "gw" && f.ref === id);
    if (answer.op === "error") throw new GatewayError(0, String(answer.code), String(answer.message));
    return answer;
  }
  close() {
    this.ws.close(1e3, "bye");
  }
};

// link/ash-link.ts
async function streamBack(send, sid, res, extra = {}) {
  const headers = [];
  res.headers.forEach((v, k) => {
    if (!/^(set-cookie|content-length|content-encoding|transfer-encoding|connection)$/i.test(k)) headers.push([k, v]);
  });
  send({ t: "tun", op: "http.head", sid, status: res.status, headers, ...extra });
  if (res.body) {
    let buf = [];
    let size = 0;
    const flush = () => {
      const all = Buffer.concat(buf);
      for (let i = 0; i < all.length; i += LIMITS.tunnelChunkBytes) {
        send({ t: "tun", op: "http.body", sid, data: b64u(new Uint8Array(all.subarray(i, i + LIMITS.tunnelChunkBytes))), ...extra });
      }
      buf = [];
      size = 0;
    };
    for await (const chunk of res.body) {
      buf.push(chunk);
      size += chunk.length;
      if (size >= LIMITS.tunnelChunkBytes || (res.headers.get("content-type") ?? "").includes("event-stream")) flush();
    }
    if (size) flush();
  }
  send({ t: "tun", op: "http.end", sid, ...extra });
}
var log = (...a) => console.log((/* @__PURE__ */ new Date()).toISOString(), ...a);
async function loadOrCreateKey(stateDir) {
  const file = join(stateDir, "device.jwk");
  if (existsSync(file)) return DeviceKey.fromJwk(JSON.parse(readFileSync(file, "utf8")));
  const key = await DeviceKey.generate();
  writeFileSync(file, JSON.stringify(await key.exportJwk()), { mode: 384 });
  log("generated device key", key.id);
  return key;
}
function controlToken(stateDir) {
  return secretToken(stateDir, "control-token");
}
function secretToken(stateDir, name) {
  const file = join(stateDir, name);
  if (existsSync(file)) return readFileSync(file, "utf8").trim();
  const t = randomToken(24);
  writeFileSync(file, t, { mode: 384 });
  return t;
}
var Engine = class {
  constructor(cfg) {
    this.cfg = cfg;
    this.origin = new URL(cfg.url).origin;
  }
  cfg;
  cookie = null;
  cookieFor = null;
  origin;
  tokenUrl() {
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
  async auth(force = false) {
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
  headers(from, cookie) {
    const h = new Headers();
    for (const [k, v] of from) {
      if (/^(host|origin|referer|cookie|sec-fetch-.*|accept-encoding)$/i.test(k)) continue;
      h.append(k, v);
    }
    if (from.some(([k]) => k.toLowerCase() === "origin")) h.set("origin", this.origin);
    if (cookie) h.set("cookie", cookie);
    return h;
  }
};
var Owner = class {
  constructor(gw, engine) {
    this.gw = gw;
    this.engine = engine;
  }
  gw;
  engine;
  conn = null;
  httpReqs = /* @__PURE__ */ new Map();
  sockets = /* @__PURE__ */ new Map();
  pending = /* @__PURE__ */ new Map();
  /** Requests this phone sent to a device (MCP proxy), waiting for / streaming the device's answer. */
  outbound = /* @__PURE__ */ new Map();
  connected = false;
  async run() {
    let delay = 1e3;
    for (; ; ) {
      try {
        const session = await this.gw.authenticate();
        const conn = await this.gw.connect(session);
        this.conn = conn;
        this.connected = true;
        delay = 1e3;
        log("connected to gateway as owner", this.gw.key.id);
        conn.onUnmatched = (f) => this.onFrame(f);
        const keepalive = setInterval(() => conn.ws.readyState === WebSocket.OPEN && conn.ws.send("ping"), 3e4);
        const pend = await conn.request({ op: "pair.pending" }).catch(() => null);
        for (const r of pend?.requests ?? []) {
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
      delay = Math.min(delay * 2, 3e4);
    }
  }
  send(frame) {
    const c = this.conn;
    if (c && c.ws.readyState === WebSocket.OPEN) c.ws.send(JSON.stringify(frame));
  }
  onFrame(f) {
    if (f.t === "tun" && typeof f.sid === "string" && this.outbound.has(f.sid)) return this.onOutbound(f);
    if (f.t === "gw" && f.op === "pair.request") {
      shortFingerprint(String(f.pubkey)).then((fingerprint) => {
        this.pending.set(String(f.request_id), { request_id: String(f.request_id), client_id: String(f.client_id), name: String(f.name), pubkey: String(f.pubkey), fingerprint, at: Date.now() });
        log(`pairing request from "${f.name}" (${fingerprint}) \u2014 approve it on the control page`);
      });
      return;
    }
    if (f.t !== "tun") return;
    const sid = String(f.sid);
    switch (f.op) {
      case "http.req":
        this.httpReqs.set(sid, { method: String(f.method), path: String(f.path), headers: f.headers ?? [], body: [] });
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
        s?.ws.close(1e3);
        return;
      }
    }
  }
  async proxyHttp(sid, req) {
    const body = req.body.length ? Buffer.concat(req.body) : void 0;
    let res = null;
    for (let attempt = 0; attempt < 2; attempt++) {
      const cookie = await this.engine.auth(attempt > 0);
      res = await fetch(this.engine.origin + req.path, { method: req.method, headers: this.engine.headers(req.headers, cookie), body, redirect: "manual" });
      if (res.status !== 401) break;
    }
    if (!res) throw new Error("engine unreachable");
    await streamBack((f) => this.send(f), sid, res);
  }
  openWs(sid, path) {
    this.engine.auth().then((cookie) => {
      const url = this.engine.origin.replace(/^http/, "ws") + path;
      const ws = new WebSocket(url, { headers: { ...cookie ? { cookie } : {}, origin: this.engine.origin } });
      ws.binaryType = "arraybuffer";
      const entry = { ws, queue: [], parts: [] };
      this.sockets.set(sid, entry);
      ws.addEventListener("open", () => {
        this.send({ t: "tun", op: "ws.opened", sid });
        for (const m of entry.queue) ws.send(m);
        entry.queue = [];
      });
      ws.addEventListener("message", (ev) => {
        const binary = typeof ev.data !== "string";
        const payload = binary ? b64u(new Uint8Array(ev.data)) : ev.data;
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
  onOutbound(f) {
    const o = this.outbound.get(String(f.sid));
    switch (f.op) {
      case "http.head":
        return o.head({ status: Number(f.status), headers: f.headers ?? [] });
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
  forward(to, req, res) {
    if (!this.conn) {
      res.writeHead(503, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "offline", message: "not connected to the gateway" }));
      return;
    }
    const sid = randomToken(12);
    let started = false;
    const timer = setTimeout(() => this.outbound.get(sid)?.end("device did not answer in time"), 15e4);
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
      }
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
  async grant() {
    const c = this.requireConn();
    return Number((await c.request({ op: "device.list" })).grant_version) + 1;
  }
  requireConn() {
    if (!this.conn) throw new GatewayError(503, "offline", "not connected to the gateway");
    return this.conn;
  }
  async ticket() {
    return { ticket: await this.gw.createPairTicket(this.requireConn()), expires_in: 300 };
  }
  async approve(requestId, permissions) {
    const r = this.pending.get(requestId);
    if (!r) throw new GatewayError(404, "unknown_request", "no such pending request");
    await this.gw.approve(this.requireConn(), r, permissions, await this.grant());
    this.pending.delete(requestId);
  }
  async reject(requestId) {
    await this.requireConn().request({ op: "pair.reject", request_id: requestId });
    this.pending.delete(requestId);
  }
  async revoke(clientId) {
    await this.gw.revoke(this.requireConn(), clientId, await this.grant());
  }
  async devices() {
    return this.conn ? (await this.conn.request({ op: "device.list" })).devices : [];
  }
};
function serveControl(owner, port, token, fingerprint) {
  const send = (res, status, body, type = "application/json") => {
    res.writeHead(status, { "content-type": `${type}; charset=utf-8`, "cache-control": "no-store" });
    res.end(typeof body === "string" ? body : JSON.stringify(body));
  };
  const readBody = (req) => new Promise((ok) => {
    let s = "";
    req.on("data", (d) => s += d);
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
          devices: await owner.devices().catch(() => [])
        });
      }
      if (req.method !== "POST") return send(res, 404, { error: "not_found" });
      const body = await readBody(req);
      if (url.pathname === "/api/ticket") return send(res, 200, await owner.ticket());
      if (url.pathname === "/api/approve") {
        await owner.approve(String(body.request_id), body.permissions ?? ["chat"]);
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
var CONTROL_PAGE = `<!doctype html><html lang="zh"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ash \xB7 \u8BBE\u5907</title><style>
body{font:15px/1.6 system-ui,sans-serif;margin:0;background:#f6f7f9;color:#1d2430}main{max-width:32rem;margin:0 auto;padding:1.2rem}
section{background:#fff;border-radius:12px;padding:1rem 1.2rem;margin:1rem 0;box-shadow:0 1px 8px #0001}h2{font-size:1.05rem;margin:0 0 .5rem}
button{padding:.45rem .9rem;border:0;border-radius:7px;background:#3d63f5;color:#fff;font-size:.95rem;margin:.2rem .3rem .2rem 0}
button.gray{background:#8b95a5}code{background:#eef1f6;padding:.1rem .35rem;border-radius:5px;word-break:break-all}.muted{color:#7a8595;font-size:.85rem}
</style></head><body><main><h1>Ash \xB7 \u8BBE\u5907</h1><div id="v">\u52A0\u8F7D\u4E2D\u2026</div></main><script>
const post=(p,b)=>fetch(p,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(b||{})}).then(r=>r.json());
const esc=s=>String(s).replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]));
let ticket=null;
async function render(){const s=await fetch("/api/state").then(r=>r.json());
let h='<section><h2>\u7F51\u5173</h2><p>'+(s.connected?"\u{1F7E2} \u5DF2\u8FDE\u63A5":"\u{1F534} \u672A\u8FDE\u63A5")+' <span class="muted">'+esc(s.gateway)+'</span></p><p class="muted">\u624B\u673A\u6307\u7EB9 <code>'+esc(s.owner_fingerprint)+'</code></p></section>';
h+='<section><h2>\u6DFB\u52A0\u8BBE\u5907</h2><button onclick="mk()">\u751F\u6210\u914D\u5BF9\u7801</button>'+(ticket?'<p>\u5728\u65B0\u8BBE\u5907\u4E0A\u6253\u5F00 <code>'+esc(s.gateway)+'</code>\uFF0C\u7C98\u8D34\u914D\u5BF9\u7801\uFF085 \u5206\u949F\u5185\u6709\u6548\uFF09\uFF1A</p><p><code>'+esc(ticket)+'</code></p>':'')+'</section>';
h+='<section><h2>\u5F85\u786E\u8BA4</h2>'+(s.pending.length?s.pending.map(p=>'<p><b>'+esc(p.name)+'</b><br><span class="muted">\u8BBE\u5907\u6307\u7EB9</span> <code>'+esc(p.fingerprint)+'</code><br><label><input type="checkbox" id="w_'+p.request_id+'" checked> \u7F51\u9875\u7AEF\uFF08\u5B8C\u6574\u754C\u9762\uFF09</label><br><label><input type="checkbox" id="x_'+p.request_id+'"> \u5F00\u653E\u672C\u673A\u5DE5\u5177\u7ED9 Agent\uFF08\u7B14\u8BB0\u672C\u7B49\uFF09</label><br><button onclick="ok(\\''+p.request_id+'\\')">\u6279\u51C6</button><button class="gray" onclick="no(\\''+p.request_id+'\\')">\u62D2\u7EDD</button></p>').join(''):'<p class="muted">\u6CA1\u6709</p>')+'</section>';
h+='<section><h2>\u5DF2\u914D\u5BF9</h2>'+(s.devices.length?s.devices.map(d=>'<p>'+(d.online?"\u{1F7E2} ":"\u26AA\uFE0F ")+esc(d.name)+' <span class="muted">'+esc(d.permissions.join(", "))+(d.revoked?" \xB7 \u5DF2\u64A4\u9500":"")+'</span>'+(d.revoked?'':' <button class="gray" onclick="rv(\\''+d.id+'\\')">\u64A4\u9500</button>')+'</p>').join(''):'<p class="muted">\u6CA1\u6709</p>')+'</section>';
document.getElementById("v").innerHTML=h;}
async function mk(){const r=await post("/api/ticket");ticket=r.ticket;render();}
async function ok(id){const perms=["chat"];if(document.getElementById("w_"+id).checked)perms.push("web_ui");if(document.getElementById("x_"+id).checked)perms.push("expose_capability");await post("/api/approve",{request_id:id,permissions:perms});render();}
async function no(id){await post("/api/reject",{request_id:id});render();}
async function rv(id){if(confirm("\u64A4\u9500\u8FD9\u4E2A\u8BBE\u5907\uFF1F"))await post("/api/revoke",{client_id:id});render();}
render();setInterval(render,3000);
</script></body></html>`;
function serveMcpProxy(owner, port, token) {
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
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => {
      const headers = [];
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === "string" && !/^(host|connection|content-length|x-ash-link|transfer-encoding)$/i.test(k)) headers.push([k, v]);
      }
      owner.forward(m[1], { method: req.method ?? "GET", path: `/mcp/${m[2]}${m[3] ?? ""}`, headers, body: chunks.length ? [Buffer.concat(chunks)] : [] }, res);
    });
  }).listen(port, "127.0.0.1", () => log(`MCP proxy for DSH on http://127.0.0.1:${port}/d/<device>/<server>`));
}
var StdioMcp = class {
  constructor(name, spec) {
    this.name = name;
    this.spec = spec;
  }
  name;
  spec;
  child = null;
  waiting = /* @__PURE__ */ new Map();
  buf = "";
  ensure() {
    if (this.child && this.child.exitCode === null) return this.child;
    const child = spawn(this.spec.command, this.spec.args ?? [], { cwd: this.spec.cwd, env: { ...process.env, ...this.spec.env }, stdio: ["pipe", "pipe", "pipe"] });
    child.stderr.on("data", (d) => log(`[mcp ${this.name}]`, String(d).trim()));
    child.stdout.on("data", (d) => {
      this.buf += String(d);
      let nl;
      while ((nl = this.buf.indexOf("\n")) >= 0) {
        const line = this.buf.slice(0, nl).trim();
        this.buf = this.buf.slice(nl + 1);
        if (!line) continue;
        try {
          const msg = JSON.parse(line);
          const key = JSON.stringify(msg.id);
          if (msg.id !== void 0 && msg.method === void 0 && this.waiting.has(key)) {
            this.waiting.get(key)(msg);
            this.waiting.delete(key);
          }
        } catch {
          log(`[mcp ${this.name}] non-JSON output:`, line.slice(0, 200));
        }
      }
    });
    child.on("exit", (code) => {
      log(`[mcp ${this.name}] exited`, code);
      for (const [, w] of this.waiting) w({ jsonrpc: "2.0", id: null, error: { code: -32e3, message: "MCP server exited" } });
      this.waiting.clear();
    });
    this.child = child;
    log(`[mcp ${this.name}] started: ${this.spec.command} ${(this.spec.args ?? []).join(" ")}`);
    return child;
  }
  async handle(method, bodyText) {
    if (method === "GET") return new Response(null, { status: 405, headers: { allow: "POST, DELETE" } });
    if (method === "DELETE") return new Response(null, { status: 200 });
    if (method !== "POST") return new Response(null, { status: 405 });
    let parsed;
    try {
      parsed = JSON.parse(bodyText);
    } catch {
      return Response.json({ jsonrpc: "2.0", id: null, error: { code: -32700, message: "parse error" } }, { status: 400 });
    }
    const msgs = Array.isArray(parsed) ? parsed : [parsed];
    const child = this.ensure();
    const answers = msgs.filter((m) => m.method !== void 0 && m.id !== void 0).map(
      (m) => new Promise((resolve) => {
        const key = JSON.stringify(m.id);
        const t = setTimeout(() => {
          this.waiting.delete(key);
          resolve({ jsonrpc: "2.0", id: m.id, error: { code: -32001, message: "MCP server timed out" } });
        }, 12e4);
        this.waiting.set(key, (msg) => (clearTimeout(t), resolve(msg)));
      })
    );
    for (const m of msgs) child.stdin.write(JSON.stringify(m) + "\n");
    if (answers.length === 0) return new Response(null, { status: 202 });
    const out = await Promise.all(answers);
    return Response.json(Array.isArray(parsed) ? out : out[0]);
  }
};
var Device = class {
  constructor(gw, servers) {
    this.gw = gw;
    this.servers = servers;
    for (const [name, spec] of Object.entries(servers)) if ("command" in spec) this.stdio.set(name, new StdioMcp(name, spec));
  }
  gw;
  servers;
  conn = null;
  reqs = /* @__PURE__ */ new Map();
  stdio = /* @__PURE__ */ new Map();
  async run() {
    let delay = 1e3;
    for (; ; ) {
      try {
        const conn = await this.gw.connect(await this.gw.authenticate());
        this.conn = conn;
        delay = 1e3;
        log(`connected to gateway as device ${this.gw.key.id}; serving MCP: ${Object.keys(this.servers).join(", ") || "(none)"}`);
        conn.onUnmatched = (f) => this.onFrame(f);
        const keepalive = setInterval(() => conn.ws.readyState === WebSocket.OPEN && conn.ws.send("ping"), 3e4);
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
      delay = Math.min(delay * 2, 3e4);
    }
  }
  send(f) {
    const c = this.conn;
    if (c && c.ws.readyState === WebSocket.OPEN) c.ws.send(JSON.stringify(f));
  }
  onFrame(f) {
    if (f.t !== "tun") return;
    const sid = String(f.sid);
    if (f.op === "http.req") this.reqs.set(sid, { method: String(f.method), path: String(f.path), headers: f.headers ?? [], body: [] });
    else if (f.op === "http.reqbody") this.reqs.get(sid)?.body.push(fromB64u(String(f.data)));
    else if (f.op === "http.reqend") {
      const req = this.reqs.get(sid);
      this.reqs.delete(sid);
      if (req) this.serve(sid, req).catch((e) => this.send({ t: "tun", op: "http.error", sid, message: String(e?.message ?? e) }));
    }
  }
  async serve(sid, req) {
    const m = /^\/mcp\/([A-Za-z0-9_-]{1,32})(\/.*)?$/.exec(req.path.split("?")[0]);
    const spec = m ? this.servers[m[1]] : void 0;
    let res;
    if (!m || !spec) res = Response.json({ error: "unknown_server", servers: Object.keys(this.servers) }, { status: 404 });
    else if ("url" in spec) {
      const headers = new Headers();
      for (const [k, v] of req.headers) if (!/^(host|origin|cookie)$/i.test(k)) headers.append(k, v);
      res = await fetch(spec.url + (m[2] ?? ""), { method: req.method, headers, body: req.body.length ? Buffer.concat(req.body) : void 0 });
    } else res = await this.stdio.get(m[1]).handle(req.method, Buffer.concat(req.body).toString("utf8"));
    await streamBack((f) => this.send(f), sid, res);
  }
};
function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}
async function main() {
  const arg = (flag) => {
    const i = process.argv.indexOf(flag);
    return i >= 0 ? process.argv[i + 1] : void 0;
  };
  const cfgPath = arg("--config");
  if (!cfgPath) throw new Error("usage: ash-link --config <file> [--pair <code>]");
  const cfg = JSON.parse(readFileSync(cfgPath, "utf8"));
  mkdirSync(cfg.stateDir, { recursive: true, mode: 448 });
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
      const grant = await gw.waitForApproval(pr.request_id, pr.owner_key, 10 * 6e4);
      writeFileSync(pairedFile, JSON.stringify({ owner_key: pr.owner_key, owner_id: pr.owner_id, ...grant }), { mode: 384 });
      log("paired with permissions", grant.permissions.join(", "));
      if (!grant.permissions.includes("expose_capability")) log("note: the phone did not grant expose_capability, so it cannot call this device's tools");
    }
    await new Device(gw, cfg.mcp ?? {}).run();
    return;
  }
  for (; ; ) {
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
      await sleep(15e3);
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
