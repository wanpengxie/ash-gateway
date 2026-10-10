/** The fields of a stored pairing request the owner is told about. */
export interface PairRequestInfo { id: string; client_id: string; name: string; pubkey: string; ticket_hash: string }

/**
 * `ticket_hash` is base64url(SHA-256(ticket)) — the same value the owner registered with
 * `pair.ticket` — so the owner can tell which of several waiting pairings a request belongs to
 * without ever seeing the ticket itself.
 */
export function pairRequestFrame(r: PairRequestInfo, fingerprint: string): Record<string, unknown> {
  return { t: "gw", op: "pair.request", request_id: r.id, client_id: r.client_id, name: r.name, pubkey: r.pubkey, fingerprint, ticket_hash: r.ticket_hash };
}

export function pairPendingEntry(r: PairRequestInfo): Record<string, unknown> {
  return { request_id: r.id, client_id: r.client_id, name: r.name, pubkey: r.pubkey, ticket_hash: r.ticket_hash };
}
