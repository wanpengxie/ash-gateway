// End-to-end test against a running gateway (wrangler dev or a deployment).
//
//   GATEWAY_URL=http://127.0.0.1:8787 BOOTSTRAP_SECRET=... npm run e2e
//
// Plays both the Agent phone (owner) and a laptop (client). A fresh gateway gets
// claimed by a throwaway owner key which is saved to .e2e-owner.json so the test
// can be re-run; do not point this at a gateway your real phone should claim.

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { DeviceKey, GatewayClient, GatewayError } from "../client/client";
import { type Envelope, randomToken } from "../src/protocol";

const BASE = (process.env.GATEWAY_URL ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const SECRET = process.env.BOOTSTRAP_SECRET ?? "";
const OWNER_FILE = ".e2e-owner.json";

let passed = 0;
function ok(cond: unknown, what: string): void {
  if (!cond) throw new Error(`FAILED: ${what}`);
  passed++;
  console.log(`  ✓ ${what}`);
}

async function rejects(p: Promise<unknown>, code: string, what: string): Promise<void> {
  try {
    await p;
  } catch (e) {
    if (e instanceof GatewayError && e.code === code) return ok(true, `${what} → ${code}`);
    throw new Error(`FAILED: ${what}: expected ${code}, got ${e instanceof Error ? e.message : String(e)}`);
  }
  throw new Error(`FAILED: ${what}: expected ${code}, but it succeeded`);
}

async function main(): Promise<void> {
  console.log(`gateway: ${BASE}`);
  const probe = new GatewayClient(BASE, await DeviceKey.generate());

  // ---------------------------------------------------------------- claim
  console.log("claim");
  let owner: GatewayClient;
  const h0 = await probe.health();
  ok(h0.ok === true && h0.protocol === "ash-gw/1", "health answers");
  if (!h0.claimed) {
    if (!SECRET) throw new Error("gateway is unclaimed: set BOOTSTRAP_SECRET");
    const intruder = new GatewayClient(BASE, await DeviceKey.generate());
    await rejects(intruder.claim("not-the-secret"), "bad_mac", "claim with a wrong secret");
    owner = new GatewayClient(BASE, await DeviceKey.generate());
    const claimed = await owner.claim(SECRET, "e2e phone");
    ok(claimed.owner_id === owner.key.id, "claim with the right secret makes this key the owner");
    writeFileSync(OWNER_FILE, JSON.stringify({ base: BASE, jwk: await owner.key.exportJwk() }));
  } else {
    if (!existsSync(OWNER_FILE)) throw new Error(`gateway already claimed and ${OWNER_FILE} is missing (reset the gateway first)`);
    const saved = JSON.parse(readFileSync(OWNER_FILE, "utf8"));
    owner = new GatewayClient(BASE, await DeviceKey.fromJwk(saved.jwk));
    ok(h0.owner_id === owner.key.id, "gateway is owned by the saved e2e owner key");
  }
  await rejects(probe.claim(SECRET || "x"), "already_claimed", "second claim");

  // ---------------------------------------------------------------- auth
  console.log("auth");
  await rejects(probe.authenticate(), "unknown_device", "unpaired device authenticates");
  const ownerSession = await owner.authenticate();
  ok(ownerSession.role === "owner", "owner gets a session");
  {
    // replaying a used challenge must fail
    const res = await fetch(`${BASE}/v1/auth/challenge`, { method: "POST", body: JSON.stringify({ device_id: owner.key.id }) });
    const { nonce } = (await res.json()) as { nonce: string };
    const { ctx } = await import("../src/protocol");
    const body = JSON.stringify({ device_id: owner.key.id, nonce, sig: await owner.key.sign(ctx.auth(owner.origin, owner.key.id, nonce)) });
    const first = await fetch(`${BASE}/v1/auth/session`, { method: "POST", body });
    const second = await fetch(`${BASE}/v1/auth/session`, { method: "POST", body });
    ok(first.status === 200 && second.status === 401, "a signed challenge can be used exactly once");
    const wrongOrigin = await fetch(`${BASE}/v1/auth/challenge`, {
      method: "POST",
      headers: { origin: "https://evil.example" },
      body: JSON.stringify({ device_id: owner.key.id }),
    });
    ok(wrongOrigin.status === 403, "browser request from a foreign origin is refused");
  }
  await expectWsRefused(`${BASE.replace(/^http/, "ws")}/v1/ws`, [], "websocket without a session is refused");
  await expectWsRefused(`${BASE.replace(/^http/, "ws")}/v1/ws`, ["ash.v1", `ash.bearer.${randomToken()}`], "websocket with a made-up session is refused");

  const phone = await owner.connect(ownerSession);
  const hello = await phone.next((f) => f.op === "hello");
  ok(hello.role === "owner" && hello.device_id === owner.key.id, "owner websocket is authenticated before upgrade");

  // ---------------------------------------------------------------- pairing
  console.log("pairing");
  const list0 = await phone.request({ op: "device.list" });
  let grant = Number(list0.grant_version);
  const ticket = await owner.createPairTicket(phone);
  const laptop = new GatewayClient(BASE, await DeviceKey.generate());
  await rejects(laptop.requestPairing(randomToken(24), "laptop"), "ticket_invalid", "pairing with a made-up ticket");
  const pr = await laptop.requestPairing(ticket, "e2e laptop");
  ok(pr.owner_key === owner.key.publicKey, "gateway reports the owner key the QR code pinned");
  await rejects(new GatewayClient(BASE, await DeviceKey.generate()).requestPairing(ticket, "second"), "ticket_used", "reusing a ticket");
  const note = await phone.next((f) => f.op === "pair.request");
  ok(note.client_id === laptop.key.id && note.name === "e2e laptop", "phone is notified of the pending device");
  await rejects(laptop.authenticate(), "unknown_device", "pending device cannot log in before approval");
  await rejects(
    phone.request({ op: "pair.approve", request_id: pr.request_id, permissions: ["chat"], grant_version: grant + 1, sig: await owner.key.sign(new Uint8Array([1])) }),
    "bad_signature",
    "approval with a bad owner signature",
  );
  await owner.approve(phone, { request_id: pr.request_id, client_id: note.client_id as string, pubkey: note.pubkey as string }, ["chat", "read_status"], ++grant);
  const grantInfo = await laptop.waitForApproval(pr.request_id, owner.key.publicKey);
  ok(grantInfo.permissions.join() === "chat,read_status", "client verifies the owner-signed approval");

  // ---------------------------------------------------------------- relay
  console.log("relay");
  const clientSession = await laptop.authenticate();
  const pc = await laptop.connect(clientSession);
  const chello = await pc.next((f) => f.op === "hello");
  ok(chello.role === "client" && chello.owner_online === true, "client sees the phone online");

  const msg = await laptop.envelope("agent.message", "owner", { text: "你好，Ash" });
  pc.send(msg);
  const got = (await phone.next((f) => f.message_id === msg.message_id)) as unknown as Envelope;
  ok(await GatewayClient.verifyEnvelope(got, laptop.key.publicKey), "phone receives the client's envelope with a valid signature");
  ok(JSON.parse(got.payload).text === "你好，Ash", "payload arrives byte-for-byte");
  ok((await pc.next((f) => f.op === "delivered" && f.message_id === msg.message_id)).to === owner.key.id, "sender gets a delivered receipt");

  const answer = await owner.envelope("agent.event", laptop.key.id, { text: "收到" }, { replyTo: msg.message_id });
  phone.send(answer);
  const back = (await pc.next((f) => f.message_id === answer.message_id)) as unknown as Envelope;
  ok(back.reply_to === msg.message_id && (await GatewayClient.verifyEnvelope(back, owner.key.publicKey)), "client receives the phone's signed reply");

  const spoof = await laptop.envelope("agent.message", "owner", { text: "x" });
  pc.send({ ...spoof, from: owner.key.id });
  ok((await pc.next((f) => f.op === "error" && f.message_id === spoof.message_id)).code === "from_mismatch", "a client cannot send as someone else");

  const stale = await laptop.envelope("agent.message", "owner", { text: "late" }, { ttlMs: -1 });
  pc.send(stale);
  ok((await pc.next((f) => f.op === "error" && f.message_id === stale.message_id)).code === "expired", "expired envelopes are dropped");

  const sideways = await laptop.envelope("agent.message", laptop.key.id, { text: "x" });
  pc.send(sideways);
  ok((await pc.next((f) => f.op === "error" && f.message_id === sideways.message_id)).code === "forbidden_route", "clients can only address the phone");

  // ---------------------------------------------------------------- offline
  console.log("offline");
  phone.close();
  ok((await pc.next((f) => f.op === "presence" && f.owner_online === false)).owner_online === false, "client is told the phone went offline");
  const lost = await laptop.envelope("agent.message", "owner", { text: "anyone?" });
  pc.send(lost);
  ok((await pc.next((f) => f.op === "error" && f.message_id === lost.message_id)).code === "device_offline", "sending to an offline phone reports device_offline (nothing is queued)");
  const phone2 = await owner.connect(await owner.authenticate());
  await phone2.next((f) => f.op === "hello");
  ok((await pc.next((f) => f.op === "presence" && f.owner_online === true)).owner_online === true, "client is told the phone is back");

  // ---------------------------------------------------------------- revoke
  console.log("revoke");
  await rejects(owner.revoke(phone2, laptop.key.id, grant), "stale_grant", "revocation must move the grant version forward");
  await owner.revoke(phone2, laptop.key.id, ++grant);
  ok((await pc.closed).code === 4003, "revoked client's live connection is closed");
  await rejects(laptop.authenticate(), "unknown_device", "revoked client cannot log in again");
  const list1 = await phone2.request({ op: "device.list" });
  ok((list1.devices as { id: string; revoked: boolean }[]).some((d) => d.id === laptop.key.id && d.revoked), "device list shows the revocation");
  phone2.close();

  console.log(`\nall ${passed} checks passed`);
}

async function expectWsRefused(url: string, protocols: string[], what: string): Promise<void> {
  const ws = new WebSocket(url, protocols);
  const outcome = await new Promise<string>((resolve) => {
    ws.addEventListener("open", () => resolve("open"));
    ws.addEventListener("error", () => resolve("error"));
    ws.addEventListener("close", () => resolve("error"));
    setTimeout(() => resolve("timeout"), 10_000);
  });
  if (outcome === "open") ws.close();
  ok(outcome === "error", what);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
