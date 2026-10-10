import { test } from "node:test";
import assert from "node:assert/strict";
import { pairPendingEntry, pairRequestFrame } from "../src/pairing";
import { sha256b64u } from "../src/protocol";

const row = { id: "r1", client_id: "c1", name: "laptop", pubkey: "PK", ticket_hash: "" };

test("pair.request and pair.pending carry the ticket hash (base64url SHA-256 of the ticket)", async () => {
  const ticket = "ticket-ticket-ticket-12345678";
  const ticket_hash = await sha256b64u(ticket);
  assert.match(ticket_hash, /^[A-Za-z0-9_-]{43}$/);
  const frame = pairRequestFrame({ ...row, ticket_hash }, "ab:cd");
  assert.deepEqual(frame, { t: "gw", op: "pair.request", request_id: "r1", client_id: "c1", name: "laptop", pubkey: "PK", fingerprint: "ab:cd", ticket_hash });
  assert.deepEqual(pairPendingEntry({ ...row, ticket_hash }), { request_id: "r1", client_id: "c1", name: "laptop", pubkey: "PK", ticket_hash });
  assert.ok(!JSON.stringify(frame).includes(ticket), "the ticket itself is never sent");
});

test("two waiting pairings are told apart by their ticket hash", async () => {
  const a = pairPendingEntry({ ...row, id: "a", ticket_hash: await sha256b64u("aaaaaaaa") });
  const b = pairPendingEntry({ ...row, id: "b", ticket_hash: await sha256b64u("bbbbbbbb") });
  assert.notEqual(a.ticket_hash, b.ticket_hash);
});
