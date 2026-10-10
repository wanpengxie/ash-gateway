// Tunnel end-to-end test: browser → gateway → phone, and phone → gateway → laptop.
//
//   GATEWAY_URL=http://127.0.0.1:8787 BOOTSTRAP_SECRET=... npm run tunnel-e2e   (fresh, unclaimed gateway)
//
// The phone and the laptop are small fixtures built on the reference client (the real device
// side is ash core, in the ash repo). The phone answers tunneled browser requests itself: an
// index page, a large asset, a JSON echo, an event stream, and a WebSocket echo.

import { randomBytes } from "node:crypto";
import { Connection, DeviceKey, GatewayClient } from "../client/client";
import { b64u, fromB64u, LIMITS } from "../src/protocol";

const BASE = (process.env.GATEWAY_URL ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const SECRET = process.env.BOOTSTRAP_SECRET ?? "";
if (!["127.0.0.1", "localhost", "[::1]"].includes(new URL(BASE).hostname)) throw new Error("This test only runs against a local gateway");
const BIG = randomBytes(1024 * 1024 + 123); // forces several tunnel chunks

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

// ------------------------------------------------------------------ phone fixture

const phoneKey = await DeviceKey.generate();
const phoneGw = new GatewayClient(BASE, phoneKey);
let phone: Connection;
const seenFrom = new Set<string>();
const aborted = new Set<string>();
const presence: { device_id: string; online: boolean }[] = [];
const reqs = new Map<string, { method: string; path: string; body: Uint8Array[]; from: string }>();

function send(f: Record<string, unknown>) {
  phone.ws.send(JSON.stringify(f));
}
function reply(sid: string, status: number, headers: [string, string][], body: Uint8Array) {
  send({ t: "tun", op: "http.head", sid, status, headers });
  for (let i = 0; i < body.length; i += LIMITS.tunnelChunkBytes) send({ t: "tun", op: "http.body", sid, data: b64u(new Uint8Array(body.subarray(i, i + LIMITS.tunnelChunkBytes))) });
  send({ t: "tun", op: "http.end", sid });
}

function onPhoneFrame(f: Record<string, any>) {
  if (f.t === "gw" && f.op === "device.presence") return void presence.push({ device_id: f.device_id, online: f.online });
  if (f.t !== "tun") return;
  const sid = String(f.sid);
}

// ------------------------------------------------------------------ laptop fixture

async function startLaptop(ticket: string, permissions: string[]) {
  const key = await DeviceKey.generate();
  const gw = new GatewayClient(BASE, key);
  const pr = await gw.requestPairing(ticket, "e2e laptop");
  await until(() => false, 800);
  await phoneGw.approve(phone, { request_id: pr.request_id, client_id: key.id, pubkey: key.publicKey }, permissions as never, await nextGrant());
  await gw.waitForApproval(pr.request_id, pr.owner_key);
  const conn = await gw.connect(await gw.authenticate());
  return { key, conn };
}

async function nextGrant(): Promise<number> {
  return Number((await phone.request({ op: "device.list" })).grant_version) + 1;
}

async function pairBrowser(webUi: boolean): Promise<{ key: DeviceKey; cookie: string }> {
  const ticket = await phoneGw.createPairTicket(phone);
  const key = await DeviceKey.generate();
  const gw = new GatewayClient(BASE, key);
  const pr = await gw.requestPairing(ticket, webUi ? "e2e browser" : "e2e chat-only");
  await phoneGw.approve(phone, { request_id: pr.request_id, client_id: key.id, pubkey: key.publicKey }, (webUi ? ["chat", "web_ui"] : ["chat"]) as never, await nextGrant());
  await gw.waitForApproval(pr.request_id, pr.owner_key);
  const s = await gw.authenticate();
  return { key, cookie: `ash_session=${s.token}` };
}

// ------------------------------------------------------------------ run

console.log(`gateway ${BASE}\nphone`);
await phoneGw.claim(SECRET, "tunnel-e2e phone");
phone = await phoneGw.connect(await phoneGw.authenticate());
phone.onUnmatched = onPhoneFrame;
ok(true, "the phone claims the gateway and connects as owner");

console.log("browser");
const anon = await fetch(`${BASE}/`, { headers: { accept: "text/html" } });
ok(anon.status === 401 && (await anon.text()).includes("配对码"), "unpaired browser gets the pairing page");
const pwa = await fetch(`${BASE}/manifest.webmanifest`);
ok(pwa.status === 200 && ((await pwa.json()) as { name: string }).name === "Ash", "the web app manifest is public (installable page)");
const browser = await pairBrowser(true);
const H = (extra: Record<string, string> = {}) => ({ cookie: browser.cookie, ...extra });

const index = await fetch(`${BASE}/`, { headers: H({ accept: "text/html" }) });
ok(index.status === 200 && (await index.text()).includes("fixture phone"), "a paired browser loads the phone's UI through the tunnel");
ok(index.headers.get("set-cookie") === null, "cookies set by the phone never reach the browser");
ok(seenFrom.has(browser.key.id), "the phone learns which paired device is calling");

const big = Buffer.from(await (await fetch(`${BASE}/big.bin`, { headers: H() })).arrayBuffer());
ok(big.equals(BIG), `a ${BIG.length}-byte response arrives intact (chunked)`);

const echo = await fetch(`${BASE}/api/echo`, { method: "POST", headers: H({ "content-type": "application/json", origin: new URL(BASE).origin }), body: JSON.stringify({ hi: "你好" }) });
const echoed = (await echo.json()) as { got: string };
ok(echo.status === 200 && JSON.parse(echoed.got).hi === "你好", "POST bodies reach the phone");

const ac = new AbortController();
const stream = await fetch(`${BASE}/api/events/stream`, { headers: H({ accept: "text/event-stream" }), signal: ac.signal });
const reader = stream.body!.getReader();
const first = new TextDecoder().decode((await reader.read()).value);
ok(stream.headers.get("content-type")?.includes("event-stream") && first.includes('"n":1'), "an event stream flows chunk by chunk");
ac.abort();
ok(await until(() => aborted.size > 0, 15_000), "when the browser drops the stream, the phone is told to stop (http.abort)");

const ws = new WebSocket(`${BASE.replace(/^http/, "ws")}/ws-echo`, { headers: H({ origin: new URL(BASE).origin }) } as unknown as string[]);
ws.binaryType = "arraybuffer";
const inbox: (string | ArrayBuffer)[] = [];
ws.addEventListener("message", (e) => inbox.push(e.data as string | ArrayBuffer));
await new Promise<void>((r, j) => {
  ws.addEventListener("open", () => r());
  ws.addEventListener("error", () => j(new Error("tunnel websocket failed")));
});
ws.send("hello");
ok((await until(() => inbox.length > 0)) && inbox.shift() === "echo:hello", "WebSocket frames round-trip through the tunnel");
ws.close();

const chatOnly = await pairBrowser(false);
ok((await fetch(`${BASE}/`, { headers: { cookie: chatOnly.cookie, accept: "text/html" } })).status === 403, "a device without web_ui cannot open the UI");
ok((await fetch(`${BASE}/api/echo`, { method: "POST", body: "{}" })).status === 401, "requests without a session never reach the phone");

console.log("laptop");
const laptop = await startLaptop(await phoneGw.createPairTicket(phone), ["chat", "expose_capability"]);
laptop.conn.onStream(s => s.onMessage(m => s.send(typeof m === "string" ? `echo:${m}` : m)));
const duplex = phone.openStream(laptop.key.id); // path "/link"
const streamReplies: (string | Uint8Array)[] = [];
duplex.onMessage(m => streamReplies.push(m));
const largeText = "你好🚀".repeat(60_000);
duplex.send(largeText);
ok(await until(() => streamReplies.length > 0) && streamReplies[0] === `echo:${largeText}`, "device duplex stream reassembles large Unicode messages");
let replaced = false;
duplex.onClose(r => { replaced = r.code === 4409; });
const replacement = phone.openStream(laptop.key.id);
ok(await until(() => replaced), "new device stream closes the previous stream");
let peerGone = false;
replacement.onClose(r => { peerGone = r.code === 4410; });
ok(await until(() => presence.some((p) => p.device_id === laptop.key.id && p.online)), "the phone is told when its laptop comes online (device.presence)");
const legacy = phone.openStream(laptop.key.id, "/ash/device/stream");
ok(await new Promise<boolean>(r => legacy.onClose(x => r(x.code === 4404))), "the old /ash/device/stream path is refused");
phone.send({ t: "tun", op: "http.req", sid: "h1", to: laptop.key.id, method: "GET", path: "/ash/manifest", headers: [] });
ok((await phone.next(f => f.op === "http.error" && f.sid === "h1")).message === "http_tunnel_removed", "device HTTP tunnels are refused");
const chatOnlyStream = phone.openStream(chatOnly.key.id);
ok(await new Promise<boolean>(r => chatOnlyStream.onClose(x => r(x.code === 4404))), "devices without expose_capability receive no tunnel traffic");
laptop.conn.close();
ok(await until(() => peerGone), "device disconnect closes its stream at the phone");
ok(await until(() => presence.some((p) => p.device_id === laptop.key.id && !p.online)), "the phone is told when its laptop goes away");
const afterGone = phone.openStream(laptop.key.id);
ok(await new Promise<boolean>(r => afterGone.onClose(x => r(x.code === 4404))), "a laptop that went away reports offline");

console.log("offline");
phone.close();
await sleep(1500);
ok((await fetch(`${BASE}/`, { headers: H({ accept: "text/html" }) })).status === 503, "with the phone offline the browser is told so (nothing is queued)");

console.log(`\nall ${passed} checks passed`);
process.exit(0);
