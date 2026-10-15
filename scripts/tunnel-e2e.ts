// Device tunnel end-to-end test: phone → gateway → laptop on path /link, the only tunnel there is.
//
//   GATEWAY_URL=http://127.0.0.1:8787 BOOTSTRAP_SECRET=... npm run tunnel-e2e   (fresh, unclaimed gateway)
//
// The phone and the laptop are small fixtures built on the reference client (the real ends are ash
// core and its computer program, in the ash repo, which run end-to-end encryption inside the tunnel).
// The gateway passes the stream's messages on without reading them.

import { Connection, DeviceKey, GatewayClient } from "../client/client";

const BASE = (process.env.GATEWAY_URL ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const SECRET = process.env.BOOTSTRAP_SECRET ?? "";
if (!["127.0.0.1", "localhost", "[::1]"].includes(new URL(BASE).hostname)) throw new Error("This test only runs against a local gateway");

let passed = 0;
function ok(cond: unknown, what: string): void {
  if (!cond) throw new Error(`FAILED: ${what}`);
  passed++;
  console.log(`  ✓ ${what}`);
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const until = async (pred: () => boolean, ms = 10_000) => {
  for (let t = 0; t < ms && !pred(); t += 100) await sleep(100);
  return pred();
};

// ------------------------------------------------------------------ phone

const phoneKey = await DeviceKey.generate();
const phoneGw = new GatewayClient(BASE, phoneKey);
let phone: Connection;
const presence: { device_id: string; online: boolean }[] = [];

async function nextGrant(): Promise<number> {
  return Number((await phone.request({ op: "device.list" })).grant_version) + 1;
}

/** A device paired with [permissions], signed in and connected. */
async function startDevice(name: string, permissions: string[]) {
  const ticket = await phoneGw.createPairTicket(phone);
  const key = await DeviceKey.generate();
  const gw = new GatewayClient(BASE, key);
  const pr = await gw.requestPairing(ticket, name);
  await phoneGw.approve(phone, { request_id: pr.request_id, client_id: key.id, pubkey: key.publicKey }, permissions as never, await nextGrant());
  await gw.waitForApproval(pr.request_id, pr.owner_key);
  const conn = await gw.connect(await gw.authenticate());
  return { key, conn };
}

// ------------------------------------------------------------------ run

console.log(`gateway ${BASE}\nphone`);
await phoneGw.claim(SECRET, "tunnel-e2e phone");
phone = await phoneGw.connect(await phoneGw.authenticate());
phone.onUnmatched = (f) => { if (f.t === "gw" && f.op === "device.presence") presence.push({ device_id: String(f.device_id), online: Boolean(f.online) }); };
ok(true, "the phone claims the gateway and connects as owner");
phone.send({ t: "tun", op: "ws.msg", sid: "x", text: "to nobody" });
ok((await phone.next((f) => f.op === "error")).code === "bad_frame", "a tunnel frame that names no device is refused (there is no browser tunnel)");
ok((await fetch(`${BASE}/`, { headers: { accept: "text/html" } })).status === 404, "the relay serves no page");

console.log("laptop");
const laptop = await startDevice("e2e laptop", ["chat", "expose_capability"]);
laptop.conn.onStream((s) => s.onMessage((m) => s.send(typeof m === "string" ? `echo:${m}` : m)));
ok(await until(() => presence.some((p) => p.device_id === laptop.key.id && p.online)), "the phone is told when its laptop comes online (device.presence)");
const duplex = phone.openStream(laptop.key.id); // path "/link"
const replies: (string | Uint8Array)[] = [];
duplex.onMessage((m) => replies.push(m));
const largeText = "你好🚀".repeat(60_000);
duplex.send(largeText);
ok(await until(() => replies.length > 0) && replies[0] === `echo:${largeText}`, "the /link stream carries a large message both ways, reassembled");
const opaque = Buffer.from("not readable by the relay").toString("base64");
duplex.send(opaque);
ok(await until(() => replies.length > 1) && replies[1] === `echo:${opaque}`, "opaque (encrypted, base64) text passes unchanged");
let replaced = false;
duplex.onClose((r) => { replaced = r.code === 4409; });
const replacement = phone.openStream(laptop.key.id);
ok(await until(() => replaced), "a new stream to the same device closes the previous one");
let peerGone = false;
replacement.onClose((r) => { peerGone = r.code === 4410; });
const legacy = phone.openStream(laptop.key.id, "/ash/device/stream");
ok(await new Promise<boolean>((r) => legacy.onClose((x) => r(x.code === 4404))), "any path but /link is refused");
phone.send({ t: "tun", op: "http.req", sid: "h1", to: laptop.key.id, method: "GET", path: "/ash/manifest", headers: [] });
ok((await phone.next((f) => f.op === "http.error" && f.sid === "h1")).message === "http_tunnel_removed", "device HTTP tunnels are refused");

const chatOnly = await startDevice("e2e chat-only", ["chat"]);
const chatOnlyStream = phone.openStream(chatOnly.key.id);
ok(await new Promise<boolean>((r) => chatOnlyStream.onClose((x) => r(x.code === 4404))), "devices without expose_capability receive no tunnel traffic");

laptop.conn.close();
ok(await until(() => peerGone), "device disconnect closes its stream at the phone");
ok(await until(() => presence.some((p) => p.device_id === laptop.key.id && !p.online)), "the phone is told when its laptop goes away");
const afterGone = phone.openStream(laptop.key.id);
ok(await new Promise<boolean>((r) => afterGone.onClose((x) => r(x.code === 4404))), "a laptop that went away reports offline");

chatOnly.conn.close();
phone.close();
console.log(`\nall ${passed} checks passed`);
process.exit(0);
