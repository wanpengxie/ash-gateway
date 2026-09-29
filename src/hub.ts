// GatewayHub: the one SQLite-backed Durable Object of a deployment.
//
// Holds only what the gateway needs to run: device public keys, grants,
// revocations, short-lived challenges / sessions / pairing tickets. Never
// conversations, memory, files or queued commands — when the phone is offline
// the sender gets `device_offline` and decides itself when to retry.
//
// Atomicity rule used throughout: do every `await` (signature checks, hashing)
// first, then check-and-mutate in one synchronous stretch of SQL. A Durable
// Object may interleave other events at an await, never inside synchronous code.

import { DurableObject } from "cloudflare:workers";
import type { Env } from "./env";
import { json } from "./http";
import {
  ctx as signCtx,
  deviceIdForKey,
  type Envelope,
  hmacSha256,
  importPublicKey,
  LIMITS,
  PERMISSIONS,
  PROTOCOL,
  ProtocolError,
  randomToken,
  type Role,
  sha256b64u,
  shortFingerprint,
  timingSafeEqual,
  verifySignature,
} from "./protocol";

export const GATEWAY_VERSION = "0.1.0";

interface Attachment {
  id: string;
  role: Role;
  /** Origin the device connected through; owner signatures made on this socket are bound to it. */
  origin: string;
}

interface DeviceRow {
  id: string;
  role: Role;
  pubkey: string;
  name: string;
  permissions: string;
  grant_version: number;
  created_at: number;
  revoked: number;
  [k: string]: SqlStorageValue;
}

interface PairRequestRow {
  id: string;
  client_id: string;
  pubkey: string;
  name: string;
  status: "pending" | "approved" | "rejected";
  approval: string | null;
  expires_at: number;
  [k: string]: SqlStorageValue;
}

export class GatewayHub extends DurableObject<Env> {
  private readonly sql: SqlStorage;

  constructor(state: DurableObjectState, env: Env) {
    super(state, env);
    this.sql = state.storage.sql;
    this.migrate();
    // Application-level keepalive answered by the runtime without waking the object.
    state.setWebSocketAutoResponse(new WebSocketRequestResponsePair("ping", "pong"));
  }

  // ------------------------------------------------------------------ storage

  private migrate(): void {
    this.sql.exec(`
      CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS devices (
        id TEXT PRIMARY KEY, role TEXT NOT NULL, pubkey TEXT NOT NULL, name TEXT NOT NULL,
        permissions TEXT NOT NULL, grant_version INTEGER NOT NULL, created_at INTEGER NOT NULL,
        revoked INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS challenges (
        nonce TEXT PRIMARY KEY, purpose TEXT NOT NULL, subject TEXT NOT NULL, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY, device_id TEXT NOT NULL, expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS pair_tickets (
        ticket_hash TEXT PRIMARY KEY, expires_at INTEGER NOT NULL, used INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS pair_requests (
        id TEXT PRIMARY KEY, client_id TEXT NOT NULL, pubkey TEXT NOT NULL, name TEXT NOT NULL,
        status TEXT NOT NULL, approval TEXT, expires_at INTEGER NOT NULL);
    `);
    // Lost-phone reset: only someone who controls the Cloudflare account can change
    // RESET_EPOCH (a deployment variable); a public request can never wipe the gateway.
    const epoch = this.env.RESET_EPOCH ?? "0";
    const stored = this.meta("reset_epoch");
    if (stored !== null && stored !== epoch) {
      this.sql.exec(`DELETE FROM devices; DELETE FROM challenges; DELETE FROM sessions;
        DELETE FROM pair_tickets; DELETE FROM pair_requests; DELETE FROM meta;`);
      for (const ws of this.ctx.getWebSockets()) ws.close(4010, "gateway reset");
    }
    this.setMeta("reset_epoch", epoch);
  }

  private meta(key: string): string | null {
    const row = this.sql.exec<{ value: string }>("SELECT value FROM meta WHERE key = ?", key).toArray()[0];
    return row ? row.value : null;
  }

  private setMeta(key: string, value: string): void {
    this.sql.exec("INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value);
  }

  private owner(): DeviceRow | null {
    return this.sql.exec<DeviceRow>("SELECT * FROM devices WHERE role = 'owner' AND revoked = 0").toArray()[0] ?? null;
  }

  private device(id: string): DeviceRow | null {
    return this.sql.exec<DeviceRow>("SELECT * FROM devices WHERE id = ?", id).toArray()[0] ?? null;
  }

  private grantVersion(): number {
    return Number(this.meta("grant_version") ?? "0");
  }

  private purgeExpired(now: number): void {
    this.sql.exec("DELETE FROM challenges WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM sessions WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM pair_tickets WHERE expires_at <= ?", now);
    this.sql.exec("DELETE FROM pair_requests WHERE expires_at <= ?", now);
  }

  private newChallenge(purpose: string, subject: string): { nonce: string; expires_at: number } {
    const now = Date.now();
    this.purgeExpired(now);
    const live = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM challenges").one().n;
    if (live >= LIMITS.maxLiveChallenges) throw new ProtocolError("rate_limited", "too many pending challenges", 429);
    const nonce = randomToken(24);
    const expires_at = now + LIMITS.challengeTtlMs;
    this.sql.exec("INSERT INTO challenges (nonce, purpose, subject, expires_at) VALUES (?, ?, ?, ?)", nonce, purpose, subject, expires_at);
    return { nonce, expires_at };
  }

  /** Consume a challenge exactly once. Synchronous on purpose (see file header). */
  private consumeChallenge(nonce: string, purpose: string, subject: string): boolean {
    const row = this.sql
      .exec<{ n: number }>(
        "SELECT COUNT(*) AS n FROM challenges WHERE nonce = ? AND purpose = ? AND subject = ? AND expires_at > ?",
        nonce,
        purpose,
        subject,
        Date.now(),
      )
      .one();
    this.sql.exec("DELETE FROM challenges WHERE nonce = ?", nonce);
    return row.n === 1;
  }

  // ------------------------------------------------------------------ HTTP

  override async fetch(request: Request): Promise<Response> {
    const url = new URL(request.url);
    const origin = request.headers.get("x-ash-origin") ?? url.origin;
    try {
      const route = `${request.method} ${url.pathname}`;
      switch (route) {
        case "GET /v1/health":
          return this.health();
        case "GET /v1/ws":
          return await this.upgrade(request, origin);
      }
      if (request.method !== "POST") return json(404, { error: "not_found" });
      const body = await readJson(request);
      switch (url.pathname) {
        case "/v1/bootstrap/challenge":
          return this.bootstrapChallenge();
        case "/v1/bootstrap/claim":
          return await this.bootstrapClaim(origin, body);
        case "/v1/auth/challenge":
          return this.authChallenge(body);
        case "/v1/auth/session":
          return await this.authSession(origin, body);
        case "/v1/pair/request":
          return await this.pairRequest(body);
        case "/v1/pair/status":
          return this.pairStatus(body);
      }
      return json(404, { error: "not_found" });
    } catch (e) {
      if (e instanceof ProtocolError) return json(e.status, { error: e.code, message: e.message });
      console.error("hub error", e);
      return json(500, { error: "internal" });
    }
  }

  private health(): Response {
    const owner = this.owner();
    return json(200, {
      ok: true,
      protocol: PROTOCOL,
      version: GATEWAY_VERSION,
      claimed: owner !== null,
      owner_id: owner?.id ?? null,
      owner_online: owner !== null && this.ctx.getWebSockets(`dev:${owner.id}`).length > 0,
      bootstrap_configured: Boolean(this.env.BOOTSTRAP_SECRET),
    });
  }

  private bootstrapChallenge(): Response {
    if (!this.env.BOOTSTRAP_SECRET) throw new ProtocolError("bootstrap_not_configured", "BOOTSTRAP_SECRET is not set on this deployment", 503);
    if (this.owner()) throw new ProtocolError("already_claimed", "this gateway already has an owner", 409);
    return json(200, this.newChallenge("bootstrap", ""));
  }

  /**
   * First claim: the Agent phone proves it knows BOOTSTRAP_SECRET (HMAC) and holds
   * the private key it registers (signature). Never first-come-first-served.
   */
  private async bootstrapClaim(origin: string, body: Record<string, unknown>): Promise<Response> {
    const secret = this.env.BOOTSTRAP_SECRET;
    if (!secret) throw new ProtocolError("bootstrap_not_configured", "BOOTSTRAP_SECRET is not set on this deployment", 503);
    const ownerKey = str(body, "owner_key");
    const nonce = str(body, "nonce");
    const mac = str(body, "mac");
    const sig = str(body, "sig");
    const name = optName(body);
    const data = signCtx.bootstrapClaim(origin, nonce, ownerKey);
    const macOk = timingSafeEqual(await hmacSha256(secret, data), mac);
    const sigOk = macOk && (await verifySignature(ownerKey, sig, data));
    const ownerId = await deviceIdForKey(ownerKey);

    const fresh = this.consumeChallenge(nonce, "bootstrap", "");
    if (!fresh) throw new ProtocolError("challenge_invalid", "unknown, used or expired challenge", 401);
    if (!macOk) throw new ProtocolError("bad_mac", "bootstrap secret proof does not match", 401);
    if (!sigOk) throw new ProtocolError("bad_signature", "owner key signature does not verify", 401);
    if (this.owner()) throw new ProtocolError("already_claimed", "this gateway already has an owner", 409);
    const now = Date.now();
    this.sql.exec(
      "INSERT INTO devices (id, role, pubkey, name, permissions, grant_version, created_at) VALUES (?, 'owner', ?, ?, '[]', 0, ?) " +
        "ON CONFLICT(id) DO UPDATE SET role = 'owner', pubkey = excluded.pubkey, name = excluded.name, revoked = 0",
      ownerId,
      ownerKey,
      name ?? "agent phone",
      now,
    );
    this.setMeta("claimed_at", String(now));
    return json(200, { owner_id: ownerId, fingerprint: await shortFingerprint(ownerKey) });
  }

  private authChallenge(body: Record<string, unknown>): Response {
    const deviceId = str(body, "device_id");
    const dev = this.device(deviceId);
    if (!dev || dev.revoked) throw new ProtocolError("unknown_device", "device is not registered", 404);
    return json(200, this.newChallenge("auth", deviceId));
  }

  private async authSession(origin: string, body: Record<string, unknown>): Promise<Response> {
    const deviceId = str(body, "device_id");
    const nonce = str(body, "nonce");
    const sig = str(body, "sig");
    const dev = this.device(deviceId);
    if (!dev || dev.revoked) throw new ProtocolError("unknown_device", "device is not registered", 404);
    const sigOk = await verifySignature(dev.pubkey, sig, signCtx.auth(origin, deviceId, nonce));
    const token = randomToken(32);
    const tokenHash = await sha256b64u(token);

    const fresh = this.consumeChallenge(nonce, "auth", deviceId);
    if (!fresh) throw new ProtocolError("challenge_invalid", "unknown, used or expired challenge", 401);
    if (!sigOk) throw new ProtocolError("bad_signature", "signature does not verify", 401);
    const now = this.device(deviceId);
    if (!now || now.revoked) throw new ProtocolError("unknown_device", "device is not registered", 404);
    const expires_at = Date.now() + LIMITS.sessionTtlMs;
    this.sql.exec("INSERT INTO sessions (token_hash, device_id, expires_at) VALUES (?, ?, ?)", tokenHash, deviceId, expires_at);
    // Browsers get an HttpOnly cookie (used by the same-origin WebSocket upgrade);
    // native clients use the returned token as a Bearer credential.
    const cookie = `ash_session=${token}; Path=/v1/; Max-Age=${Math.floor(LIMITS.sessionTtlMs / 1000)}; Secure; HttpOnly; SameSite=Strict`;
    return json(200, { token, expires_at, device_id: deviceId, role: dev.role }, { "set-cookie": cookie });
  }

  private async pairRequest(body: Record<string, unknown>): Promise<Response> {
    const ticket = str(body, "ticket");
    const pubkey = str(body, "pubkey");
    const name = optName(body) ?? "unnamed device";
    await importPublicKey(pubkey);
    const clientId = await deviceIdForKey(pubkey);
    const ticketHash = await sha256b64u(ticket);
    const fingerprint = await shortFingerprint(pubkey);

    const now = Date.now();
    this.purgeExpired(now);
    const owner = this.owner();
    if (!owner) throw new ProtocolError("not_claimed", "gateway has no owner yet", 409);
    const t = this.sql.exec<{ used: number }>("SELECT used FROM pair_tickets WHERE ticket_hash = ?", ticketHash).toArray()[0];
    if (!t) throw new ProtocolError("ticket_invalid", "unknown or expired pairing ticket", 404);
    if (t.used) throw new ProtocolError("ticket_used", "pairing ticket already used", 409);
    const existing = this.device(clientId);
    if (existing && !existing.revoked) throw new ProtocolError("already_paired", "this key is already paired", 409);
    this.sql.exec("UPDATE pair_tickets SET used = 1 WHERE ticket_hash = ?", ticketHash);
    const requestId = randomToken(16);
    this.sql.exec(
      "INSERT INTO pair_requests (id, client_id, pubkey, name, status, expires_at) VALUES (?, ?, ?, ?, 'pending', ?)",
      requestId,
      clientId,
      pubkey,
      name,
      now + LIMITS.pairRequestTtlMs,
    );
    this.sendTo(owner.id, { t: "gw", op: "pair.request", request_id: requestId, client_id: clientId, name, pubkey, fingerprint });
    return json(200, {
      request_id: requestId,
      client_id: clientId,
      status: "pending",
      owner_id: owner.id,
      owner_key: owner.pubkey,
      owner_fingerprint: await shortFingerprint(owner.pubkey),
    });
  }

  private pairStatus(body: Record<string, unknown>): Response {
    const requestId = str(body, "request_id");
    const r = this.sql.exec<PairRequestRow>("SELECT * FROM pair_requests WHERE id = ? AND expires_at > ?", requestId, Date.now()).toArray()[0];
    if (!r) return json(404, { error: "unknown_request", status: "expired" });
    const out: Record<string, unknown> = { request_id: r.id, client_id: r.client_id, status: r.status };
    if (r.status === "approved" && r.approval) Object.assign(out, JSON.parse(r.approval));
    return json(200, out);
  }

  // ------------------------------------------------------------------ WebSocket

  private async upgrade(request: Request, origin: string): Promise<Response> {
    if (request.headers.get("upgrade")?.toLowerCase() !== "websocket") throw new ProtocolError("expected_websocket", "use a WebSocket upgrade", 426);
    // Authenticate BEFORE accepting the upgrade.
    const { token, subprotocol } = sessionToken(request);
    if (!token) throw new ProtocolError("unauthorized", "missing session", 401);
    const tokenHash = await sha256b64u(token);
    const s = this.sql
      .exec<{ device_id: string }>("SELECT device_id FROM sessions WHERE token_hash = ? AND expires_at > ?", tokenHash, Date.now())
      .toArray()[0];
    if (!s) throw new ProtocolError("unauthorized", "invalid or expired session", 401);
    const dev = this.device(s.device_id);
    if (!dev || dev.revoked) throw new ProtocolError("unauthorized", "device revoked", 401);

    if (dev.role === "owner") {
      // One Agent phone: a new owner connection replaces the old one.
      for (const old of this.ctx.getWebSockets(`dev:${dev.id}`)) old.close(4000, "replaced by a newer connection");
    }
    const pair = new WebSocketPair();
    const [client, server] = Object.values(pair) as [WebSocket, WebSocket];
    this.ctx.acceptWebSocket(server, [`dev:${dev.id}`, `role:${dev.role}`]);
    server.serializeAttachment({ id: dev.id, role: dev.role, origin } satisfies Attachment);
    const owner = this.owner();
    server.send(
      JSON.stringify({
        t: "gw",
        op: "hello",
        device_id: dev.id,
        role: dev.role,
        owner_id: owner?.id ?? null,
        owner_online: dev.role === "owner" || (owner !== null && this.ctx.getWebSockets(`dev:${owner.id}`).length > 0),
      }),
    );
    if (dev.role === "owner") this.broadcastPresence(true);
    return new Response(null, {
      status: 101,
      webSocket: client,
      headers: subprotocol ? { "sec-websocket-protocol": subprotocol } : {},
    });
  }

  override async webSocketMessage(ws: WebSocket, message: string | ArrayBuffer): Promise<void> {
    const me = ws.deserializeAttachment() as Attachment | null;
    if (!me) return ws.close(4001, "no identity");
    if (typeof message !== "string") return this.reply(ws, { t: "gw", op: "error", code: "binary_not_supported" });
    if (message.length > LIMITS.maxFrameBytes) return this.reply(ws, { t: "gw", op: "error", code: "frame_too_large" });
    let frame: Record<string, unknown>;
    try {
      frame = JSON.parse(message);
    } catch {
      return this.reply(ws, { t: "gw", op: "error", code: "bad_json" });
    }
    if (typeof frame !== "object" || frame === null) return this.reply(ws, { t: "gw", op: "error", code: "bad_frame" });
    // A device revoked while connected is cut off on its next frame even if its close raced.
    const dev = this.device(me.id);
    if (!dev || dev.revoked) return ws.close(4003, "revoked");
    try {
      if (frame.t === "gw") await this.control(ws, me, dev, frame);
      else this.relay(ws, me, frame, message);
    } catch (e) {
      const code = e instanceof ProtocolError ? e.code : "internal";
      if (!(e instanceof ProtocolError)) console.error("ws error", e);
      this.reply(ws, { t: "gw", op: "error", ref: frame.id ?? null, code, message: e instanceof Error ? e.message : String(e) });
    }
  }

  override async webSocketClose(ws: WebSocket, code: number, reason: string): Promise<void> {
    const me = ws.deserializeAttachment() as Attachment | null;
    try {
      ws.close(code, reason);
    } catch {
      // already closed
    }
    if (me?.role === "owner" && this.ctx.getWebSockets(`dev:${me.id}`).filter((w) => w !== ws).length === 0) {
      this.broadcastPresence(false);
    }
  }

  override async webSocketError(ws: WebSocket): Promise<void> {
    await this.webSocketClose(ws, 1011, "error");
  }

  /** Forward a signed envelope as-is. The receiver verifies `sig`; the gateway checks routing only. */
  private relay(ws: WebSocket, me: Attachment, frame: Record<string, unknown>, raw: string): void {
    const e = frame as unknown as Envelope;
    const messageId = typeof e.message_id === "string" ? e.message_id : null;
    const fail = (code: string, message: string) => this.reply(ws, { t: "gw", op: "error", code, message, message_id: messageId });
    if (
      e.v !== 1 ||
      typeof e.type !== "string" ||
      !messageId ||
      typeof e.from !== "string" ||
      typeof e.to !== "string" ||
      typeof e.issued_at !== "number" ||
      typeof e.expires_at !== "number" ||
      typeof e.payload !== "string" ||
      typeof e.sig !== "string" ||
      !(e.reply_to === null || typeof e.reply_to === "string")
    ) {
      return fail("bad_envelope", "envelope is missing required fields");
    }
    if (e.from !== me.id) return fail("from_mismatch", "from must be the authenticated device id");
    if (e.expires_at <= Date.now()) return fail("expired", "envelope already expired");

    let target: string;
    if (me.role === "client") {
      const owner = this.owner();
      if (!owner) return fail("not_claimed", "gateway has no owner");
      if (e.to !== "owner" && e.to !== owner.id) return fail("forbidden_route", "clients may only address the agent phone");
      target = owner.id;
    } else {
      const d = this.device(e.to);
      if (!d || d.role !== "client" || d.revoked) return fail("unknown_device", "no such client");
      target = d.id;
    }
    const sockets = this.ctx.getWebSockets(`dev:${target}`);
    if (sockets.length === 0) return fail("device_offline", "target device is not connected");
    for (const s of sockets) s.send(raw);
    this.reply(ws, { t: "gw", op: "delivered", message_id: messageId, to: target });
  }

  private async control(ws: WebSocket, me: Attachment, dev: DeviceRow, frame: Record<string, unknown>): Promise<void> {
    const op = frame.op;
    const ref = frame.id ?? null;
    if (op === "presence") {
      const owner = this.owner();
      return this.reply(ws, {
        t: "gw",
        op: "presence",
        ref,
        owner_online: owner !== null && this.ctx.getWebSockets(`dev:${owner.id}`).length > 0,
        ...(me.role === "owner" ? { clients_online: this.onlineClients() } : {}),
      });
    }
    if (me.role !== "owner") throw new ProtocolError("forbidden", "owner-only operation");
    const origin = me.origin;
    switch (op) {
      case "pair.ticket": {
        const ticketHash = str(frame, "ticket_hash");
        const expiresAt = num(frame, "expires_at");
        const now = Date.now();
        if (expiresAt <= now || expiresAt > now + LIMITS.pairTicketMaxTtlMs) throw new ProtocolError("bad_ttl", "ticket must expire within 5 minutes");
        this.purgeExpired(now);
        this.sql.exec("INSERT OR REPLACE INTO pair_tickets (ticket_hash, expires_at, used) VALUES (?, ?, 0)", ticketHash, expiresAt);
        return this.reply(ws, { t: "gw", op: "pair.ticket.ok", ref });
      }
      case "pair.pending": {
        const rows = this.sql
          .exec<PairRequestRow>("SELECT * FROM pair_requests WHERE status = 'pending' AND expires_at > ?", Date.now())
          .toArray();
        return this.reply(ws, {
          t: "gw",
          op: "pair.pending.ok",
          ref,
          requests: rows.map((r) => ({ request_id: r.id, client_id: r.client_id, name: r.name, pubkey: r.pubkey })),
        });
      }
      case "pair.approve": {
        const requestId = str(frame, "request_id");
        const permissions = perms(frame);
        const grantVersion = num(frame, "grant_version");
        const sig = str(frame, "sig");
        const r = this.pendingRequest(requestId);
        const data = signCtx.pairApprove(origin, r.id, r.client_id, r.pubkey, permissions, grantVersion);
        if (!(await verifySignature(dev.pubkey, sig, data))) throw new ProtocolError("bad_signature", "approval signature does not verify");
        // --- synchronous from here: re-check and commit
        const again = this.pendingRequest(requestId);
        if (grantVersion <= this.grantVersion()) throw new ProtocolError("stale_grant", `grant_version must be > ${this.grantVersion()}`);
        const clients = this.sql.exec<{ n: number }>("SELECT COUNT(*) AS n FROM devices WHERE role = 'client' AND revoked = 0").one().n;
        if (clients >= LIMITS.maxClients) throw new ProtocolError("too_many_clients", "client limit reached");
        this.sql.exec(
          "INSERT INTO devices (id, role, pubkey, name, permissions, grant_version, created_at) VALUES (?, 'client', ?, ?, ?, ?, ?) " +
            "ON CONFLICT(id) DO UPDATE SET pubkey = excluded.pubkey, name = excluded.name, permissions = excluded.permissions, " +
            "grant_version = excluded.grant_version, revoked = 0",
          again.client_id,
          again.pubkey,
          again.name,
          JSON.stringify([...permissions].sort()),
          grantVersion,
          Date.now(),
        );
        const approval = { permissions: [...permissions].sort(), grant_version: grantVersion, approval_sig: sig, owner_key: dev.pubkey };
        this.sql.exec("UPDATE pair_requests SET status = 'approved', approval = ? WHERE id = ?", JSON.stringify(approval), requestId);
        this.setMeta("grant_version", String(grantVersion));
        return this.reply(ws, { t: "gw", op: "pair.approve.ok", ref, client_id: again.client_id });
      }
      case "pair.reject": {
        const requestId = str(frame, "request_id");
        this.pendingRequest(requestId);
        this.sql.exec("UPDATE pair_requests SET status = 'rejected' WHERE id = ?", requestId);
        return this.reply(ws, { t: "gw", op: "pair.reject.ok", ref });
      }
      case "device.revoke": {
        const clientId = str(frame, "client_id");
        const grantVersion = num(frame, "grant_version");
        const sig = str(frame, "sig");
        if (!(await verifySignature(dev.pubkey, sig, signCtx.revoke(origin, clientId, grantVersion)))) {
          throw new ProtocolError("bad_signature", "revocation signature does not verify");
        }
        const d = this.device(clientId);
        if (!d || d.role !== "client") throw new ProtocolError("unknown_device", "no such client");
        if (grantVersion <= this.grantVersion()) throw new ProtocolError("stale_grant", `grant_version must be > ${this.grantVersion()}`);
        this.sql.exec("UPDATE devices SET revoked = 1, grant_version = ? WHERE id = ?", grantVersion, clientId);
        this.sql.exec("DELETE FROM sessions WHERE device_id = ?", clientId);
        this.setMeta("grant_version", String(grantVersion));
        for (const s of this.ctx.getWebSockets(`dev:${clientId}`)) s.close(4003, "revoked");
        return this.reply(ws, { t: "gw", op: "device.revoke.ok", ref, client_id: clientId });
      }
      case "device.list": {
        const online = new Set(this.onlineClients());
        const rows = this.sql.exec<DeviceRow>("SELECT * FROM devices WHERE role = 'client' ORDER BY created_at").toArray();
        return this.reply(ws, {
          t: "gw",
          op: "device.list.ok",
          ref,
          grant_version: this.grantVersion(),
          devices: rows.map((d) => ({
            id: d.id,
            name: d.name,
            permissions: JSON.parse(d.permissions),
            grant_version: d.grant_version,
            revoked: Boolean(d.revoked),
            online: online.has(d.id),
            created_at: d.created_at,
          })),
        });
      }
    }
    throw new ProtocolError("unknown_op", `unknown control op ${String(op)}`);
  }

  private pendingRequest(requestId: string): PairRequestRow {
    const r = this.sql.exec<PairRequestRow>("SELECT * FROM pair_requests WHERE id = ? AND expires_at > ?", requestId, Date.now()).toArray()[0];
    if (!r) throw new ProtocolError("unknown_request", "unknown or expired pairing request");
    if (r.status !== "pending") throw new ProtocolError("not_pending", `request is ${r.status}`);
    return r;
  }

  private onlineClients(): string[] {
    const ids = new Set<string>();
    for (const ws of this.ctx.getWebSockets("role:client")) {
      const a = ws.deserializeAttachment() as Attachment | null;
      if (a) ids.add(a.id);
    }
    return [...ids];
  }

  private broadcastPresence(ownerOnline: boolean): void {
    const frame = JSON.stringify({ t: "gw", op: "presence", owner_online: ownerOnline });
    for (const ws of this.ctx.getWebSockets("role:client")) {
      try {
        ws.send(frame);
      } catch {
        // socket is closing
      }
    }
  }

  private sendTo(deviceId: string, frame: Record<string, unknown>): void {
    const text = JSON.stringify(frame);
    for (const ws of this.ctx.getWebSockets(`dev:${deviceId}`)) ws.send(text);
  }

  private reply(ws: WebSocket, frame: Record<string, unknown>): void {
    try {
      ws.send(JSON.stringify(frame));
    } catch {
      // socket is closing
    }
  }
}

// ------------------------------------------------------------------ helpers

async function readJson(request: Request): Promise<Record<string, unknown>> {
  const text = await request.text();
  if (text.length > LIMITS.maxBodyBytes) throw new ProtocolError("body_too_large", "request body too large", 413);
  if (text.trim() === "") return {};
  try {
    const v = JSON.parse(text);
    if (typeof v !== "object" || v === null || Array.isArray(v)) throw new Error();
    return v;
  } catch {
    throw new ProtocolError("bad_json", "body must be a JSON object");
  }
}

function str(o: Record<string, unknown>, key: string): string {
  const v = o[key];
  if (typeof v !== "string" || v.length === 0 || v.length > 4096) throw new ProtocolError("bad_request", `${key} must be a non-empty string`);
  return v;
}

function num(o: Record<string, unknown>, key: string): number {
  const v = o[key];
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < 0) throw new ProtocolError("bad_request", `${key} must be a non-negative integer`);
  return v;
}

function optName(o: Record<string, unknown>): string | null {
  const v = o.name;
  if (v === undefined || v === null) return null;
  if (typeof v !== "string" || v.length === 0 || v.length > LIMITS.maxDeviceNameLength || /[\u0000-\u001f]/.test(v)) {
    throw new ProtocolError("bad_request", "name must be 1-64 printable characters");
  }
  return v;
}

function perms(o: Record<string, unknown>): string[] {
  const v = o.permissions;
  if (!Array.isArray(v) || v.length === 0) throw new ProtocolError("bad_request", "permissions must be a non-empty array");
  for (const p of v) {
    if (!(PERMISSIONS as readonly string[]).includes(p)) throw new ProtocolError("bad_permission", `unknown permission ${String(p)}`);
  }
  return [...new Set(v as string[])];
}

/** Session token from (in order) Bearer header, ash.bearer.<token> subprotocol, or the browser cookie. */
function sessionToken(request: Request): { token: string | null; subprotocol: string | null } {
  const auth = request.headers.get("authorization");
  if (auth?.startsWith("Bearer ")) return { token: auth.slice(7).trim(), subprotocol: null };
  const protos = (request.headers.get("sec-websocket-protocol") ?? "").split(",").map((p) => p.trim());
  const bearer = protos.find((p) => p.startsWith("ash.bearer."));
  if (bearer) return { token: bearer.slice("ash.bearer.".length), subprotocol: protos.includes("ash.v1") ? "ash.v1" : bearer };
  const cookie = request.headers.get("cookie") ?? "";
  const m = /(?:^|;\s*)ash_session=([A-Za-z0-9_-]+)/.exec(cookie);
  return { token: m ? m[1] : null, subprotocol: null };
}
