// Hibernation check: open the phone and a client, stay idle long enough for the
// Durable Object to hibernate, then relay in both directions. Identities must come
// back from the socket attachments, not from constructor memory.
//
//   GATEWAY_URL=... IDLE_SECONDS=70 npm run hibernation      (after `npm run e2e` on the same gateway)

import { readFileSync } from "node:fs";
import { DeviceKey, GatewayClient } from "../client/client";
import type { Envelope } from "../src/protocol";

const BASE = (process.env.GATEWAY_URL ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const IDLE = Number(process.env.IDLE_SECONDS ?? "70");

async function main(): Promise<void> {
  const saved = JSON.parse(readFileSync(".e2e-owner.json", "utf8"));
  const owner = new GatewayClient(BASE, await DeviceKey.fromJwk(saved.jwk));
  const phone = await owner.connect(await owner.authenticate());
  await phone.next((f) => f.op === "hello");

  const { grant_version } = (await phone.request({ op: "device.list" })) as { grant_version: number };
  const laptop = new GatewayClient(BASE, await DeviceKey.generate());
  const pr = await laptop.requestPairing(await owner.createPairTicket(phone), "hibernation laptop");
  const note = await phone.next((f) => f.op === "pair.request");
  await owner.approve(phone, { request_id: pr.request_id, client_id: note.client_id as string, pubkey: note.pubkey as string }, ["chat"], grant_version + 1);
  await laptop.waitForApproval(pr.request_id, owner.key.publicKey);
  const pc = await laptop.connect(await laptop.authenticate());
  await pc.next((f) => f.op === "hello");

  console.log(`both connected; idling ${IDLE}s so the Durable Object can hibernate…`);
  const t0 = Date.now();
  // the literal "ping" is answered by the runtime without waking the object
  const keepalive = setInterval(() => pc.send("ping"), 30_000);
  await new Promise((r) => setTimeout(r, IDLE * 1000));
  clearInterval(keepalive);

  const up = await laptop.envelope("agent.message", "owner", { text: "still there?" });
  pc.send(up);
  const got = (await phone.next((f) => f.message_id === up.message_id, 20_000)) as unknown as Envelope;
  const down = await owner.envelope("agent.event", laptop.key.id, { text: "yes" }, { replyTo: up.message_id });
  phone.send(down);
  const back = (await pc.next((f) => f.message_id === down.message_id, 20_000)) as unknown as Envelope;
  const okUp = await GatewayClient.verifyEnvelope(got, laptop.key.publicKey);
  const okDown = await GatewayClient.verifyEnvelope(back, owner.key.publicKey);
  console.log(`after ${Math.round((Date.now() - t0) / 1000)}s idle: client→phone ${okUp ? "ok" : "BAD"}, phone→client ${okDown ? "ok" : "BAD"}`);

  const { grant_version: gv2 } = (await phone.request({ op: "device.list" })) as { grant_version: number };
  await owner.revoke(phone, laptop.key.id, gv2 + 1);
  phone.close();
  if (!okUp || !okDown) process.exit(1);
  console.log("hibernation check passed");
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
