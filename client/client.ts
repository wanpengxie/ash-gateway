// Reference client for the ash gateway protocol (Node >= 22 and browsers).
//
// Used by the end-to-end test both as the Agent phone (owner) and as a paired
// client. The Android app implements the same steps natively; the byte-level
// contract lives in src/protocol.ts and docs/PROTOCOL.md.

import {
  b64u,
  ctx,
  deviceIdForKey,
  type Envelope,
  envelopeSigningInput,
  hmacSha256,
  type Permission,
  randomToken,
  sha256b64u,
  verifySignature,
} from "../src/protocol";
import type { Bytes } from "../src/protocol";

/** A device identity: one P-256 key pair. The private key never leaves this object. */
export class DeviceKey {
  private constructor(
    private readonly privateKey: CryptoKey,
    readonly publicKey: string,
    readonly id: string,
  ) {}

  static async generate(): Promise<DeviceKey> {
    const pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
    return DeviceKey.fromPair(pair);
  }

  /** Test helper: persist a key as JWK (a real phone keeps it in the Android Keystore instead). */
  async exportJwk(): Promise<JsonWebKey> {
    return (await crypto.subtle.exportKey("jwk", this.privateKey)) as JsonWebKey;
  }

  static async fromJwk(jwk: JsonWebKey): Promise<DeviceKey> {
    const privateKey = await crypto.subtle.importKey("jwk", jwk, { name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    const { d: _d, ...pub } = jwk;
    const publicKey = await crypto.subtle.importKey("jwk", { ...pub, key_ops: ["verify"] }, { name: "ECDSA", namedCurve: "P-256" }, true, ["verify"]);
    return DeviceKey.fromPair({ privateKey, publicKey });
  }

  private static async fromPair(pair: CryptoKeyPair): Promise<DeviceKey> {
    const spki = b64u(new Uint8Array((await crypto.subtle.exportKey("spki", pair.publicKey)) as ArrayBuffer));
    return new DeviceKey(pair.privateKey, spki, await deviceIdForKey(spki));
  }

  async sign(data: Bytes): Promise<string> {
    return b64u(new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, this.privateKey, data)));
  }
}

export class GatewayError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(`${status} ${code}: ${message}`);
  }
}

export interface Session {
  token: string;
  expires_at: number;
  device_id: string;
  role: "owner" | "client";
}

export class GatewayClient {
  readonly origin: string;

  constructor(
    readonly baseUrl: string,
    readonly key: DeviceKey,
  ) {
    this.origin = new URL(baseUrl).origin;
  }

  async health(): Promise<Record<string, unknown>> {
    return this.call("GET", "/v1/health");
  }

  /** Owner only, once per deployment: prove knowledge of BOOTSTRAP_SECRET and possession of the key. */
  async claim(bootstrapSecret: string, name = "agent phone"): Promise<{ owner_id: string; fingerprint: string }> {
    const { nonce } = await this.call<{ nonce: string }>("POST", "/v1/bootstrap/challenge", {});
    const data = ctx.bootstrapClaim(this.origin, nonce, this.key.publicKey);
    return this.call("POST", "/v1/bootstrap/claim", {
      owner_key: this.key.publicKey,
      nonce,
      mac: await hmacSha256(bootstrapSecret, data),
      sig: await this.key.sign(data),
      name,
    });
  }

  async authenticate(): Promise<Session> {
    const { nonce } = await this.call<{ nonce: string }>("POST", "/v1/auth/challenge", { device_id: this.key.id });
    return this.call("POST", "/v1/auth/session", {
      device_id: this.key.id,
      nonce,
      sig: await this.key.sign(ctx.auth(this.origin, this.key.id, nonce)),
    });
  }

  /** New client: submit the ticket scanned from the phone and wait for the owner to decide. */
  async requestPairing(ticket: string, name: string): Promise<{ request_id: string; client_id: string; owner_key: string; owner_fingerprint: string }> {
    return this.call("POST", "/v1/pair/request", { ticket, pubkey: this.key.publicKey, name });
  }

  async pairingStatus(requestId: string): Promise<Record<string, unknown>> {
    return this.call("POST", "/v1/pair/status", { request_id: requestId });
  }

  /**
   * Poll until the owner approves or rejects. On approval the owner's signature is
   * checked against the owner key pinned from the QR code — a forged gateway cannot
   * hand out approvals.
   */
  async waitForApproval(requestId: string, pinnedOwnerKey: string, timeoutMs = 60_000): Promise<{ permissions: Permission[]; grant_version: number }> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const s = await this.pairingStatus(requestId);
      if (s.status === "rejected") throw new GatewayError(403, "pair_rejected", "owner rejected the pairing");
      if (s.status === "approved") {
        if (s.owner_key !== pinnedOwnerKey) throw new GatewayError(0, "owner_mismatch", "gateway reports a different owner key");
        const permissions = s.permissions as Permission[];
        const grant_version = s.grant_version as number;
        const data = ctx.pairApprove(this.origin, requestId, this.key.id, this.key.publicKey, permissions, grant_version);
        if (!(await verifySignature(pinnedOwnerKey, s.approval_sig as string, data))) {
          throw new GatewayError(0, "bad_approval", "approval is not signed by the pinned owner");
        }
        return { permissions, grant_version };
      }
      await new Promise((r) => setTimeout(r, 500));
    }
    throw new GatewayError(0, "timeout", "pairing not decided in time");
  }

  async connect(session: Session): Promise<Connection> {
    const wsUrl = this.baseUrl.replace(/^http/, "ws").replace(/\/$/, "") + "/v1/ws";
    // Browsers would rely on the HttpOnly cookie instead; Node's WebSocket cannot set
    // headers, so the short-lived token rides in the subprotocol list.
    const ws = new WebSocket(wsUrl, ["ash.v1", `ash.bearer.${session.token}`]);
    const conn = new Connection(ws);
    await conn.opened;
    return conn;
  }

  // ---------------------------------------------------------------- owner ops

  /** Returns the ticket to put in the QR code; the gateway only ever sees its hash. */
  async createPairTicket(conn: Connection, ttlMs = 5 * 60_000 - 1000): Promise<string> {
    const ticket = randomToken(24);
    await conn.request({ op: "pair.ticket", ticket_hash: await sha256b64u(ticket), expires_at: Date.now() + ttlMs });
    return ticket;
  }

  async approve(conn: Connection, req: { request_id: string; client_id: string; pubkey: string }, permissions: Permission[], grantVersion: number) {
    const sig = await this.key.sign(ctx.pairApprove(this.origin, req.request_id, req.client_id, req.pubkey, permissions, grantVersion));
    return conn.request({ op: "pair.approve", request_id: req.request_id, permissions, grant_version: grantVersion, sig });
  }

  async revoke(conn: Connection, clientId: string, grantVersion: number) {
    const sig = await this.key.sign(ctx.revoke(this.origin, clientId, grantVersion));
    return conn.request({ op: "device.revoke", client_id: clientId, grant_version: grantVersion, sig });
  }

  // ---------------------------------------------------------------- envelopes

  async envelope(type: string, to: string, payload: unknown, opts: { ttlMs?: number; replyTo?: string; messageId?: string } = {}): Promise<Envelope> {
    const now = Date.now();
    const unsigned: Omit<Envelope, "sig"> = {
      v: 1,
      type,
      message_id: opts.messageId ?? randomToken(12),
      from: this.key.id,
      to,
      issued_at: now,
      expires_at: now + (opts.ttlMs ?? 60_000),
      reply_to: opts.replyTo ?? null,
      payload: JSON.stringify(payload),
    };
    return { ...unsigned, sig: await this.key.sign(await envelopeSigningInput(unsigned)) };
  }

  static async verifyEnvelope(e: Envelope, senderKey: string): Promise<boolean> {
    const { sig, ...unsigned } = e;
    return verifySignature(senderKey, sig, await envelopeSigningInput(unsigned));
  }

  // ---------------------------------------------------------------- http

  private async call<T = Record<string, unknown>>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await fetch(this.baseUrl.replace(/\/$/, "") + path, {
      method,
      headers: body === undefined ? {} : { "content-type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let data: Record<string, unknown> = {};
    try {
      data = JSON.parse(text);
    } catch {
      // non-JSON error page
    }
    if (!res.ok) throw new GatewayError(res.status, String(data.error ?? "http_error"), String(data.message ?? text.slice(0, 200)));
    return data as T;
  }
}

/** A WebSocket with a frame queue, so tests can await "the next frame matching X". */
export class Connection {
  readonly opened: Promise<void>;
  readonly closed: Promise<{ code: number; reason: string }>;
  private readonly frames: Record<string, unknown>[] = [];
  private readonly waiters: { pred: (f: Record<string, unknown>) => boolean; resolve: (f: Record<string, unknown>) => void }[] = [];
  private seq = 0;
  /** Long-lived connections: frames no waiter wants go here instead of piling up in the buffer. */
  onUnmatched: ((frame: Record<string, unknown>) => void) | null = null;

  constructor(readonly ws: WebSocket) {
    this.opened = new Promise((resolve, reject) => {
      ws.addEventListener("open", () => resolve(), { once: true });
      ws.addEventListener("error", () => reject(new GatewayError(0, "ws_error", "websocket failed to open")), { once: true });
    });
    this.closed = new Promise((resolve) => {
      ws.addEventListener("close", (ev) => resolve({ code: ev.code, reason: ev.reason }), { once: true });
    });
    ws.addEventListener("message", (ev) => {
      const text = String(ev.data);
      if (text === "pong") return; // keepalive answer from the runtime (see "ping")
      let frame: Record<string, unknown>;
      try {
        frame = JSON.parse(text) as Record<string, unknown>;
      } catch {
        return;
      }
      const i = this.waiters.findIndex((w) => w.pred(frame));
      if (i >= 0) this.waiters.splice(i, 1)[0].resolve(frame);
      else if (this.onUnmatched) this.onUnmatched(frame);
      else this.frames.push(frame);
    });
  }

  send(frame: unknown): void {
    this.ws.send(typeof frame === "string" ? frame : JSON.stringify(frame));
  }

  next(pred: (f: Record<string, unknown>) => boolean, timeoutMs = 10_000): Promise<Record<string, unknown>> {
    const i = this.frames.findIndex(pred);
    if (i >= 0) return Promise.resolve(this.frames.splice(i, 1)[0]);
    return new Promise((resolve, reject) => {
      const w = { pred, resolve: (f: Record<string, unknown>) => (clearTimeout(timer), resolve(f)) };
      const timer = setTimeout(() => {
        this.waiters.splice(this.waiters.indexOf(w), 1);
        reject(new GatewayError(0, "timeout", "no matching frame"));
      }, timeoutMs);
      this.waiters.push(w);
    });
  }

  /** Send a gateway control op and wait for its ".ok" (or error) answer. */
  async request(frame: Record<string, unknown>): Promise<Record<string, unknown>> {
    const id = `r${++this.seq}`;
    this.send({ t: "gw", id, ...frame });
    const answer = await this.next((f) => f.t === "gw" && f.ref === id);
    if (answer.op === "error") throw new GatewayError(0, String(answer.code), String(answer.message));
    return answer;
  }

  close(): void {
    this.ws.close(1000, "bye");
  }
}
