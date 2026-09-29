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
const outbound = new Map<string, { status: number; body: Uint8Array[]; done: (err?: string) => void }>();

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
  const out = outbound.get(sid);
  if (out) {
    if (f.op === "http.head") out.status = f.status;
    else if (f.op === "http.body") out.body.push(fromB64u(f.data));
    else if (f.op === "http.end") out.done();
    else if (f.op === "http.error") out.done(String(f.message));
    return;
  }
  switch (f.op) {
    case "http.req":
      reqs.set(sid, { method: f.method, path: f.path, body: [], from: f.from });
      seenFrom.add(f.from);
      return;
    case "http.reqbody":
      reqs.get(sid)?.body.push(fromB64u(f.data));
      return;
    case "http.abort":
      aborted.add(sid);
      return;
    case "http.reqend": {
      const r = reqs.get(sid)!;
      reqs.delete(sid);
      if (r.path === "/") return reply(sid, 200, [["content-type", "text/html"], ["set-cookie", "leak=1"]], Buffer.from("<title>Ash</title>fixture phone"));
      if (r.path === "/big.bin") return reply(sid, 200, [["content-type", "application/octet-stream"]], BIG);
      if (r.path === "/api/echo") return reply(sid, 200, [["content-type", "application/json"]], Buffer.from(JSON.stringify({ got: Buffer.concat(r.body).toString(), from: r.from })));
      if (r.path === "/api/events/stream") {
        send({ t: "tun", op: "http.head", sid, status: 200, headers: [["content-type", "text/event-stream"]] });
        let n = 0;
        const timer = setInterval(() => {
          if (aborted.has(sid) || n > 60) return clearInterval(timer);
          send({ t: "tun", op: "http.body", sid, data: b64u(new Uint8Array(Buffer.from(`id: ${++n}\ndata: {"n":${n}}\n\n`))) });
        }, 300);
        return;
      }
      return reply(sid, 404, [], Buffer.from("nope"));
    }
    case "ws.open":
      return send({ t: "tun", op: "ws.opened", sid });
    case "ws.msg":
      if (f.more) return; // the fixture only echoes single-frame messages
      return send({ t: "tun", op: "ws.msg", sid, ...(typeof f.b64 === "string" ? { b64: f.b64 } : { text: `echo:${f.text}` }) });
  }
}

/** The phone calls one of its devices through the gateway (what ash core does for device capabilities). */
function phoneRequest(to: string, method: string, path: string, body?: unknown): Promise<{ status: number; body: string }> {
  const sid = b64u(new Uint8Array(randomBytes(9)));
  return new Promise((resolve, reject) => {
    const o = { status: 0, body: [] as Uint8Array[], done: (err?: string) => (outbound.delete(sid), err ? reject(new Error(err)) : resolve({ status: o.status, body: Buffer.concat(o.body).toString() })) };
    outbound.set(sid, o);
    send({ t: "tun", op: "http.req", sid, to, method, path, headers: [] });
    if (body !== undefined) send({ t: "tun", op: "http.reqbody", sid, to, data: b64u(new Uint8Array(Buffer.from(JSON.stringify(body)))) });
    send({ t: "tun", op: "http.reqend", sid, to });
  });
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
  const r = new Map<string, { path: string; body: Uint8Array[] }>();
  conn.onUnmatched = (f: Record<string, any>) => {
    if (f.t !== "tun") return;
    const sid = String(f.sid);
    if (f.op === "http.req") r.set(sid, { path: f.path, body: [] });
    else if (f.op === "http.reqbody") r.get(sid)?.body.push(fromB64u(f.data));
    else if (f.op === "http.reqend") {
      const q = r.get(sid)!;
      const answer = (status: number, obj: unknown) => {
        conn.ws.send(JSON.stringify({ t: "tun", op: "http.head", sid, status, headers: [["content-type", "application/json"]] }));
        conn.ws.send(JSON.stringify({ t: "tun", op: "http.body", sid, data: b64u(new Uint8Array(Buffer.from(JSON.stringify(obj)))) }));
        conn.ws.send(JSON.stringify({ t: "tun", op: "http.end", sid }));
      };
      if (q.path === "/ash/manifest") answer(200, { name: "e2e laptop", capabilities: [{ name: "fake.echo", description: "echo", input_schema: { type: "object" } }] });
      else if (q.path === "/ash/call") answer(200, { ok: true, content: [{ type: "text", text: "laptop says: " + JSON.parse(Buffer.concat(q.body).toString()).args.text }] });
      else answer(404, { error: "not_found" });
    }
  };
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
ok(await until(() => presence.some((p) => p.device_id === laptop.key.id && p.online)), "the phone is told when its laptop comes online (device.presence)");
const manifest = await phoneRequest(laptop.key.id, "GET", "/ash/manifest");
ok(manifest.status === 200 && JSON.parse(manifest.body).capabilities[0].name === "fake.echo", "the phone reads the laptop's capability manifest through the gateway");
const called = await phoneRequest(laptop.key.id, "POST", "/ash/call", { capability: "fake.echo", args: { text: "你好" } });
ok(JSON.parse(called.body).content[0].text === "laptop says: 你好", "a capability call runs on the laptop and the result comes back");
await phoneRequest(chatOnly.key.id, "GET", "/ash/manifest").then(
  () => ok(false, "devices without expose_capability receive no tunnel traffic"),
  () => ok(true, "devices without expose_capability receive no tunnel traffic"),
);
laptop.conn.close();
ok(await until(() => presence.some((p) => p.device_id === laptop.key.id && !p.online)), "the phone is told when its laptop goes away");
await phoneRequest(laptop.key.id, "GET", "/ash/manifest").then(
  () => ok(false, "a laptop that went away reports device_offline"),
  (e) => ok(/offline/.test(String(e.message)), "a laptop that went away reports device_offline"),
);

console.log("offline");
phone.close();
await sleep(1500);
ok((await fetch(`${BASE}/`, { headers: H({ accept: "text/html" }) })).status === 503, "with the phone offline the browser is told so (nothing is queued)");

console.log(`\nall ${passed} checks passed`);
process.exit(0);
