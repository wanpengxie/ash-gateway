# ash gateway protocol `ash-gw/1`

This is the byte-level contract between the gateway, the ash Android app (owner)
and clients. The reference implementation is [`client/client.ts`](../client/client.ts);
[`src/protocol.ts`](../src/protocol.ts) is normative where this text is ambiguous.

## Keys and ids

- Every device has one **ECDSA P-256** key pair. The Android app keeps its private
  key non-exportable in the Android Keystore.
- Public keys travel as **SPKI DER, base64url without padding**. This is what Java's
  `PublicKey.getEncoded()` and WebCrypto's `exportKey("spki")` return.
- **Device id** = `base64url(SHA-256(SPKI DER))`, first 22 characters.
- **Short fingerprint** (shown on screens during pairing) = the first 8 bytes of the
  same SHA-256 as hex, grouped `XXXX-XXXX-XXXX-XXXX`.
- **Signatures** use ECDSA with SHA-256. Both encodings are accepted: raw `r||s`
  (64 bytes, WebCrypto) and ASN.1 DER (Java `SHA256withECDSA`). Either way it is
  sent as base64url.

## What gets signed

Signed data is never JSON. It is UTF-8 text made of lines joined by `\n`, with no
trailing newline:

```
ash-gw/1
<purpose>
<field 1>
…
<field n>
```

A field may not contain `\n` or `\r`. `origin` is the gateway origin exactly as the
browser would print it, e.g. `https://ash-gateway.alice.workers.dev` (scheme + host
[+ port], no trailing slash). Binding it to the signature stops a signature made for
one gateway from being replayed on another.

| purpose | fields | signed by |
|---|---|---|
| `bootstrap-claim` | origin, nonce, owner_key | owner key **and** HMAC-SHA256 with `BOOTSTRAP_SECRET` (UTF-8 key) |
| `auth` | origin, device_id, nonce | the device |
| `pair-approve` | origin, request_id, client_id, client_key, permissions (sorted, comma-joined), grant_version (decimal) | owner |
| `revoke` | origin, client_id, grant_version | owner |
| `msg` | v, type, message_id, from, to, issued_at, expires_at, reply_to (empty if null), base64url(SHA-256(payload)) | envelope sender |

## HTTP

Every endpoint takes and returns JSON. Errors look like
`{"error": "<code>", "message": "…"}` and come with a 4xx/5xx status.

A request whose `Origin` header is present but does not match the gateway is refused
with `403 origin_not_allowed`. Native apps send no `Origin`. Request bodies are
limited to 16 KiB.

### Claim (once per deployment)

```
POST /v1/bootstrap/challenge {}                       → {nonce, expires_at}
POST /v1/bootstrap/claim {owner_key, nonce, mac, sig, name?}
                                                      → {owner_id, fingerprint}
```

- `mac` = base64url(HMAC-SHA256(BOOTSTRAP_SECRET, signing input))
- `sig` = the owner's signature over the same input.
- A challenge lives 60 s and is consumed by the first claim attempt, whether that
  attempt succeeds or fails.
- Other errors:
  - `503 bootstrap_not_configured`: no Secret is set, so claiming is never anonymous.
  - `409 already_claimed`.
  - `401 bad_mac`, `401 bad_signature`, `401 challenge_invalid`.

### Session

```
POST /v1/auth/challenge {device_id}                   → {nonce, expires_at}
POST /v1/auth/session   {device_id, nonce, sig}       → {token, expires_at, device_id, role}
```

- The token is valid for 15 minutes and is only used to open WebSockets.
- Browsers also get the token as a `Secure; HttpOnly; SameSite=Strict` cookie named
  `ash_session`.
- An unknown or revoked device gets `404 unknown_device`.

### Pairing (new client)

1. The owner registers a ticket over its WebSocket (`pair.ticket`, see below). The
   QR code shows three things: the gateway URL, the ticket (≥128 bit random), and
   the owner's key or fingerprint.
2. The client submits the request:

   ```
   POST /v1/pair/request {ticket, pubkey, name}
   → {request_id, client_id, status: "pending", owner_id, owner_key, owner_fingerprint}
   ```

   A ticket is single-use: a second use gets `409 ticket_used`, and an unknown or
   expired ticket gets `404 ticket_invalid`. The client must compare `owner_key`
   with the key it scanned from the QR code.
3. The owner sees a `pair.request` frame and approves or rejects it.
4. The client polls:

   ```
   POST /v1/pair/status {request_id}
   → {status: "pending" | "rejected" | "approved", …}
   ```

   Once `status` is `approved`, the response also carries `permissions`,
   `grant_version`, `approval_sig` and `owner_key`. The client verifies
   `approval_sig` against the **pinned** owner key before trusting it.

Permissions are `chat`, `read_status`, `cancel_own_task`, `request_sensitive_action`
and `expose_capability`. The phone still enforces its own policy for every tool:
holding a permission is necessary, not sufficient.

## WebSocket `GET /v1/ws`

The upgrade is authenticated before it is accepted. The token can be supplied in
any of three ways:

- `Authorization: Bearer <token>` (native);
- the subprotocol list `["ash.v1", "ash.bearer.<token>"]` — the server answers
  with `ash.v1`;
- the `ash_session` cookie (browsers).

All frames are UTF-8 JSON text, at most 64 KiB each. The literal text `ping` gets
the answer `pong` without waking the Durable Object. Protocol-level ping/pong is
also free.

### Gateway control frames `{"t":"gw", "op": …, "id"?: …}`

Answers carry `ref` = the request's `id`. Errors come back as
`{"t":"gw","op":"error","ref","code","message"}`.

| op | who | fields | answer |
|---|---|---|---|
| `hello` | server → any | device_id, role, owner_id, owner_online | sent right after connect |
| `presence` | any → server | — | `owner_online` (+ `clients_online` for the owner) |
| `presence` | server → clients | owner_online | pushed when the phone connects or drops |
| `pair.ticket` | owner | ticket_hash = base64url(SHA-256(ticket)), expires_at (≤ 5 min) | `pair.ticket.ok` |
| `pair.request` | server → owner | request_id, client_id, name, pubkey, fingerprint | — |
| `pair.pending` | owner | — | `pair.pending.ok` {requests} |
| `pair.approve` | owner | request_id, permissions, grant_version, sig | `pair.approve.ok` |
| `pair.reject` | owner | request_id | `pair.reject.ok` |
| `device.revoke` | owner | client_id, grant_version, sig | `device.revoke.ok`; the client's sockets close with code 4003 |
| `device.list` | owner | — | `device.list.ok` {grant_version, devices} |
| `delivered` | server → sender | message_id, to | the envelope was handed to the target's socket |

`grant_version` is a counter owned by the phone. Every approval or revocation must
use a value greater than the gateway's current one (`device.list` returns it);
otherwise the gateway answers `stale_grant`. This stops old signed grants from
being replayed.

A new owner connection replaces the previous one, which is closed with code 4000.
Changing `RESET_EPOCH` closes every socket with code 4010.

### Envelopes (relayed, never interpreted)

```json
{
  "v": 1,
  "type": "agent.message",
  "message_id": "…",
  "from": "<sender device id>",
  "to": "owner | <client id>",
  "issued_at": 1790000000000,
  "expires_at": 1790000060000,
  "reply_to": null,
  "payload": "{\"text\":\"…\"}",
  "sig": "…"
}
```

- `payload` is a JSON document carried **as a string**, so the signature covers the
  exact bytes.
- The gateway checks the shape, that `from` equals the authenticated device, that
  the envelope has not expired, and the route. A client may only address the phone
  (`to = "owner"` or the owner id); the phone may address any active client.
- The gateway forwards the frame unchanged and answers the sender with `delivered`.
- If the target is not connected, the sender gets `error` `device_offline`. Nothing
  is queued.

**The receiver must verify `sig`, `expires_at` and permissions itself, and must
de-duplicate on `message_id`.** Retries reuse the same `message_id`, and "delivered"
is not "executed".

Suggested envelope types:
- `agent.message` — client → phone; payload `{text}`.
- `agent.event` — phone → client; streamed output and status.
- `task.status`, `task.cancel`.
