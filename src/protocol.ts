// Wire protocol shared by the gateway, the reference client and the Android app.
//
// Everything that gets signed is a fixed, line-based byte string (never a JSON
// serialization), so that Kotlin/Java, browsers and Workers produce identical
// bytes without a canonical-JSON library:
//
//   ash-gw/1 \n <purpose> \n <field> \n <field> ...
//
// Fields are ASCII-safe strings (ids, base64url, decimal integers). A field that
// contains "\n" is rejected before signing or verifying.

export const PROTOCOL = "ash-gw/1";

/** Byte strings handed to WebCrypto (backed by a plain ArrayBuffer). */
export type Bytes = Uint8Array<ArrayBuffer>;

export const LIMITS = {
  /** HTTP request body. */
  maxBodyBytes: 16 * 1024,
  /** One WebSocket frame (envelope or control). */
  maxFrameBytes: 64 * 1024,
  /** One tunnel frame from the phone (Cloudflare's WebSocket message cap is 1 MiB). */
  maxTunnelFrameBytes: 1024 * 1024 - 1024,
  challengeTtlMs: 60_000,
  sessionTtlMs: 15 * 60_000,
  pairTicketMaxTtlMs: 5 * 60_000,
  pairRequestTtlMs: 10 * 60_000,
  pairTicketMaxAttempts: 5,
  /** Live (unexpired, unused) challenges kept at once; beyond this the gateway refuses new ones. */
  maxLiveChallenges: 256,
  maxDeviceNameLength: 64,
  maxClients: 32,
  /** Browser sessions (devices holding `web_ui`) last a working day; everything else stays short. */
  browserSessionTtlMs: 12 * 60 * 60_000,
  /** Request body accepted for tunneled web requests (uploads go through here). */
  webMaxBodyBytes: 8 * 1024 * 1024,
  /** Raw bytes per tunnel data frame (base64 keeps each frame well under the 1 MiB WebSocket cap). */
  tunnelChunkBytes: 256 * 1024,
  /** How long the gateway waits for the phone to start answering a tunneled request. */
  tunnelHeadTimeoutMs: 30_000,
} as const;

export const PERMISSIONS = [
  "chat",
  "read_status",
  "cancel_own_task",
  "request_sensitive_action",
  "expose_capability",
  /** The full ash UI through the gateway tunnel — only for the owner's own devices. */
  "web_ui",
] as const;
export type Permission = (typeof PERMISSIONS)[number];

export type Role = "owner" | "client";

/** Build the exact bytes that get signed / MACed for one purpose. */
export function signingInput(purpose: string, fields: readonly string[]): Bytes {
  for (const f of [purpose, ...fields]) {
    if (typeof f !== "string" || f.includes("\n") || f.includes("\r")) {
      throw new ProtocolError("bad_field", "signed fields must be strings without line breaks");
    }
  }
  return new TextEncoder().encode([PROTOCOL, purpose, ...fields].join("\n"));
}

/** Contexts of every signature the gateway itself checks. */
export const ctx = {
  bootstrapClaim: (origin: string, nonce: string, ownerKey: string) =>
    signingInput("bootstrap-claim", [origin, nonce, ownerKey]),
  auth: (origin: string, deviceId: string, nonce: string) => signingInput("auth", [origin, deviceId, nonce]),
  pairApprove: (
    origin: string,
    requestId: string,
    clientId: string,
    clientKey: string,
    permissions: readonly string[],
    grantVersion: number,
  ) =>
    signingInput("pair-approve", [
      origin,
      requestId,
      clientId,
      clientKey,
      [...permissions].sort().join(","),
      String(grantVersion),
    ]),
  revoke: (origin: string, clientId: string, grantVersion: number) =>
    signingInput("revoke", [origin, clientId, String(grantVersion)]),
};

/**
 * Relay envelope. The gateway only checks shape, size and that `from` is the
 * authenticated sender; the receiving device verifies `sig` itself (the gateway
 * is never the final authority for side effects).
 *
 * `payload` is a JSON document carried as a string so its signature covers the
 * exact bytes that were sent.
 */
export interface Envelope {
  v: 1;
  type: string;
  message_id: string;
  from: string;
  to: string;
  issued_at: number;
  expires_at: number;
  reply_to: string | null;
  payload: string;
  sig: string;
}

export async function envelopeSigningInput(e: Omit<Envelope, "sig">): Promise<Bytes> {
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
    payloadHash,
  ]);
}

/** Frames the gateway itself sends or accepts on a WebSocket (never relayed). */
export type ControlFrame = { t: "gw"; op: string; [k: string]: unknown };

/**
 * Tunnel frames between the gateway and the phone (`t: "tun"`). The gateway opens a
 * stream id (`sid`) per browser HTTP request or WebSocket and the phone answers on it:
 *
 *   gateway → phone  http.req {sid, method, path, headers, from}  then  http.reqbody {sid, data}*  http.reqend {sid}
 *   phone → gateway  http.head {sid, status, headers}  http.body {sid, data}*  http.end {sid} | http.error {sid, message}
 *   gateway → phone  ws.open {sid, path, protocols, from}
 *   phone → gateway  ws.opened {sid, protocol} | ws.error {sid, message}
 *   both ways        ws.msg {sid, text | b64, more?}  ws.close {sid, code, reason}
 *
 * Bodies and binary messages travel as base64 chunks of at most LIMITS.tunnelChunkBytes;
 * a ws.msg with `more: true` is continued by the next ws.msg on the same sid.
 */
export type TunnelFrame = { t: "tun"; op: string; sid: string; [k: string]: unknown };

export class ProtocolError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status = 400,
  ) {
    super(message);
  }
}

// ---------------------------------------------------------------- encoding

export function utf8(s: string): Bytes {
  return new TextEncoder().encode(s);
}

export function b64u(bytes: Bytes): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromB64u(s: string): Bytes {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new ProtocolError("bad_encoding", "expected base64url");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function randomToken(bytes = 32): string {
  return b64u(crypto.getRandomValues(new Uint8Array(bytes)));
}

export async function sha256b64u(s: string): Promise<string> {
  return b64u(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(s))));
}

/** Constant-time comparison of two strings (length is not secret). */
export function timingSafeEqual(a: string, b: string): boolean {
  const x = utf8(a);
  const y = utf8(b);
  if (x.length !== y.length) return false;
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

// ---------------------------------------------------------------- keys

/**
 * Device ids are derived from the public key: base64url(SHA-256(SPKI DER)),
 * truncated to 22 chars (132 bits). Android's PublicKey.getEncoded() and
 * WebCrypto's exportKey("spki") both produce the SPKI DER that is hashed.
 */
export async function deviceIdForKey(spkiB64u: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", fromB64u(spkiB64u)));
  return b64u(digest).slice(0, 22);
}

/** Human-comparable fingerprint shown on both screens during pairing. */
export async function shortFingerprint(spkiB64u: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", fromB64u(spkiB64u)));
  const hex = [...digest.slice(0, 8)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return hex.match(/.{4}/g)!.join("-").toUpperCase();
}

export async function importPublicKey(spkiB64u: string): Promise<CryptoKey> {
  try {
    return await crypto.subtle.importKey(
      "spki",
      fromB64u(spkiB64u),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"],
    );
  } catch {
    throw new ProtocolError("bad_key", "public key must be a P-256 SPKI in base64url");
  }
}

/**
 * Verify an ECDSA P-256 / SHA-256 signature. Accepts both the raw r||s form
 * (WebCrypto) and ASN.1 DER (Android `SHA256withECDSA`).
 */
export async function verifySignature(spkiB64u: string, sigB64u: string, data: Bytes): Promise<boolean> {
  const key = await importPublicKey(spkiB64u);
  let sig: Bytes;
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

/** ASN.1 DER ECDSA-Sig-Value → 64-byte r||s. Returns null on malformed input. */
export function derToRaw(der: Bytes): Bytes | null {
  let i = 0;
  if (der[i++] !== 0x30) return null;
  let len = der[i++];
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n !== 1) return null;
    len = der[i++];
  }
  if (len !== der.length - i) return null;
  const out = new Uint8Array(64);
  for (let part = 0; part < 2; part++) {
    if (der[i++] !== 0x02) return null;
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

export async function hmacSha256(secret: string, data: Bytes): Promise<string> {
  const key = await crypto.subtle.importKey("raw", utf8(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64u(new Uint8Array(await crypto.subtle.sign("HMAC", key, data)));
}
