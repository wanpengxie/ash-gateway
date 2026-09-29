// Tunnel end-to-end test: browser → gateway → ash-link (phone) → a fake DSH engine.
//
//   GATEWAY_URL=http://127.0.0.1:8787 BOOTSTRAP_SECRET=... npm run tunnel-e2e   (fresh, unclaimed gateway)
//
// The fake engine behaves like `dsh web` where it matters: it prints a token URL, trades
// it for a cookie bound to its loopback authority, refuses anything without that cookie
// or with a non-loopback Host/Origin, serves a big asset, echoes POSTs and echoes on
// /api/remote.mux. ash-link runs as a real child process, exactly as on the phone.

import { spawn } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, appendFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DeviceKey, GatewayClient } from "../client/client";

const BASE = (process.env.GATEWAY_URL ?? "http://127.0.0.1:8787").replace(/\/$/, "");
const SECRET = process.env.BOOTSTRAP_SECRET ?? "";
const ENGINE_PORT = 39090;
const CONTROL_PORT = 39095;
const BIG = randomBytes(1024 * 1024 + 123); // forces several tunnel chunks

let passed = 0;
function ok(cond: unknown, what: string): void {
  if (!cond) throw new Error(`FAILED: ${what}`);
  passed++;
  console.log(`  ✓ ${what}`);
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// ------------------------------------------------------------------ fake DSH engine
const dir = mkdtempSync(join(tmpdir(), "ash-tunnel-"));
const engineLog = join(dir, "dsh-web.log");
const hex = (n: number) => [...randomBytes(n)].map((b) => b.toString(16).padStart(2, "0")).join("");
const token = hex(16);
const COOKIE = `dsh-auth-x=${hex(8)}`;
const seenHosts = new Set<string>();

const engine = createServer((req, res) => {
  seenHosts.add(String(req.headers.host));
  const loopback = req.headers.host === `127.0.0.1:${ENGINE_PORT}` && (!req.headers.origin || req.headers.origin === `http://127.0.0.1:${ENGINE_PORT}`);
  if (!loopback) return res.writeHead(403).end("not loopback");
  if (req.url === `/?token=${token}`) return res.writeHead(303, { location: "./", "set-cookie": `${COOKIE}; Path=/; HttpOnly` }).end();
  if (!(req.headers.cookie ?? "").includes(COOKIE)) return res.writeHead(401).end("dsh web authentication required");
  if (req.url === "/") return res.writeHead(200, { "content-type": "text/html" }).end("<title>DeepSeek Harness</title>fake engine");
  if (req.url === "/assets/big.bin") return res.writeHead(200, { "content-type": "application/octet-stream" }).end(BIG);
  if (req.url === "/api/echo" && req.method === "POST") {
    const chunks: Buffer[] = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => res.writeHead(200, { "content-type": "application/json", "set-cookie": "leak=1" }).end(JSON.stringify({ got: Buffer.concat(chunks).toString(), ct: req.headers["content-type"] })));
    return;
  }
  res.writeHead(404).end("nope");
});
engine.on("upgrade", async (req, socket, head) => {
  const loopback = req.headers.host === `127.0.0.1:${ENGINE_PORT}` && req.headers.origin === `http://127.0.0.1:${ENGINE_PORT}`;
  if (req.url !== "/api/remote.mux" || !loopback || !(req.headers.cookie ?? "").includes(COOKIE)) {
    socket.end("HTTP/1.1 401 Unauthorized\r\n\r\n");
    return;
  }
  // minimal RFC 6455 echo server (text + binary, no fragmentation needed on loopback)
  const accept = createHash("sha1").update(req.headers["sec-websocket-key"] + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").digest("base64");
  socket.write(`HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: ${accept}\r\n\r\n`);
  let buf = Buffer.from(head);
  socket.on("data", (d: Buffer) => {
    buf = Buffer.concat([buf, d]);
    for (;;) {
      if (buf.length < 2) return;
      const op = buf[0] & 0x0f;
      let len = buf[1] & 0x7f;
      let off = 2;
      if (len === 126) (len = buf.readUInt16BE(2)), (off = 4);
      else if (len === 127) (len = Number(buf.readBigUInt64BE(2))), (off = 10);
      if (buf.length < off + 4 + len) return;
      const mask = buf.subarray(off, off + 4);
      const payload = Buffer.from(buf.subarray(off + 4, off + 4 + len)).map((b: number, i: number) => b ^ mask[i % 4]);
      buf = buf.subarray(off + 4 + len);
      if (op === 8) return socket.end();
      const reply = op === 1 ? Buffer.from(`echo:${Buffer.from(payload).toString()}`) : Buffer.from(payload);
      socket.write(Buffer.concat([frameHeader(reply.length, op), reply]));
    }
  });
});
function frameHeader(len: number, op: number): Buffer {
  if (len < 126) return Buffer.from([0x80 | op, len]);
  if (len < 65536) return Buffer.from([0x80 | op, 126, len >> 8, len & 255]);
  const h = Buffer.alloc(10);
  h[0] = 0x80 | op;
  h[1] = 127;
  h.writeBigUInt64BE(BigInt(len), 2);
  return h;
}

async function main(): Promise<void> {
  await new Promise<void>((r) => engine.listen(ENGINE_PORT, "127.0.0.1", () => r()));
  appendFileSync(engineLog, `dsh web: http://127.0.0.1:${ENGINE_PORT}/?token=${token}\n`);

  // ---------------------------------------------------------------- phone: ash-link
  const stateDir = join(dir, "state");
  const cfgFile = join(dir, "link.json");
  writeFileSync(cfgFile, JSON.stringify({ gateway: BASE, stateDir, engine: { url: `http://127.0.0.1:${ENGINE_PORT}`, log: engineLog }, control: { port: CONTROL_PORT }, name: "tunnel-e2e phone" }));
  const { mkdirSync } = await import("node:fs");
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(join(stateDir, "bootstrap-secret"), SECRET);
  const link = spawn(process.execPath, ["dist/ash-link.mjs", "--config", cfgFile], { stdio: ["ignore", "pipe", "pipe"] });
  let linkOut = "";
  link.stdout.on("data", (d) => (linkOut += d));
  link.stderr.on("data", (d) => (linkOut += d));
  process.on("exit", () => link.kill());

  console.log(`gateway ${BASE}\nphone`);
  for (let i = 0; i < 60 && !linkOut.includes("connected to gateway"); i++) await sleep(500);
  ok(linkOut.includes("claimed the gateway") && linkOut.includes("connected to gateway"), "ash-link claims the gateway and connects as owner");
  const { readFileSync } = await import("node:fs");
  const ctl = readFileSync(join(stateDir, "control-token"), "utf8").trim();
  const control = (path: string, body?: unknown) =>
    fetch(`http://127.0.0.1:${CONTROL_PORT}${path}`, { method: body ? "POST" : "GET", headers: { "x-ash-link": ctl, "content-type": "application/json" }, body: body ? JSON.stringify(body) : undefined }).then((r) => r.json() as Promise<Record<string, unknown>>);
  ok((await fetch(`http://127.0.0.1:${CONTROL_PORT}/api/state`)).status === 401, "control page refuses callers without the control token");

  // ---------------------------------------------------------------- browser
  console.log("browser");
  const anon = await fetch(`${BASE}/`, { headers: { accept: "text/html" } });
  ok(anon.status === 401 && (await anon.text()).includes("配对码"), "unpaired browser gets the pairing page");

  async function pairBrowser(webUi: boolean): Promise<{ key: DeviceKey; cookie: string }> {
    const { ticket } = (await control("/api/ticket", {})) as { ticket: string };
    const key = await DeviceKey.generate();
    const gw = new GatewayClient(BASE, key);
    const pr = await gw.requestPairing(ticket, webUi ? "e2e browser" : "e2e chat-only");
    await sleep(800);
    await control("/api/approve", { request_id: pr.request_id, permissions: webUi ? ["chat", "web_ui"] : ["chat"] });
    await gw.waitForApproval(pr.request_id, pr.owner_key);
    const s = await gw.authenticate();
    return { key, cookie: `ash_session=${s.token}` };
  }
  const browser = await pairBrowser(true);
  const H = (extra: Record<string, string> = {}) => ({ cookie: browser.cookie, ...extra });

  const index = await fetch(`${BASE}/`, { headers: H({ accept: "text/html" }) });
  ok(index.status === 200 && (await index.text()).includes("fake engine"), "paired browser loads the engine's index through the tunnel");
  ok([...seenHosts].every((h) => h === `127.0.0.1:${ENGINE_PORT}`), "the engine only ever sees loopback requests");

  const bigRes = await fetch(`${BASE}/assets/big.bin`, { headers: H() });
  const big = Buffer.from(await bigRes.arrayBuffer());
  if (!big.equals(BIG)) console.log("    big asset:", bigRes.status, big.length, "bytes, expected", BIG.length, "first diff at", big.findIndex((b: number, i: number) => b !== BIG[i]), big.subarray(0, 120).toString());
  ok(big.equals(BIG), `a ${BIG.length}-byte asset arrives intact (chunked)`);

  const echo = await fetch(`${BASE}/api/echo`, { method: "POST", headers: H({ "content-type": "application/json", origin: new URL(BASE).origin }), body: JSON.stringify({ hi: "你好" }) });
  const echoed = (await echo.json()) as { got: string; ct: string };
  ok(echo.status === 200 && JSON.parse(echoed.got).hi === "你好" && echoed.ct === "application/json", "POST bodies and headers reach the engine (Origin rewritten to loopback)");
  ok(echo.headers.get("set-cookie") === null, "engine cookies never reach the browser");

  const ws = new WebSocket(`${BASE.replace(/^http/, "ws")}/api/remote.mux`, { headers: H({ origin: new URL(BASE).origin }) } as unknown as string[]);
  ws.binaryType = "arraybuffer";
  const inbox: (string | ArrayBuffer)[] = [];
  ws.addEventListener("message", (e) => inbox.push(e.data as string | ArrayBuffer));
  await new Promise<void>((r, j) => {
    ws.addEventListener("open", () => r());
    ws.addEventListener("error", () => j(new Error("tunnel websocket failed")));
  });
  const next = async () => {
    for (let i = 0; i < 100 && inbox.length === 0; i++) await sleep(100);
    return inbox.shift();
  };
  ws.send("hello");
  ok((await next()) === "echo:hello", "WebSocket text frames round-trip through the tunnel");
  ws.send(new Uint8Array([1, 2, 3, 250]));
  const bin = await next();
  ok(bin instanceof ArrayBuffer && Buffer.from(bin).equals(Buffer.from([1, 2, 3, 250])), "binary frames round-trip");
  const large = "x".repeat(600_000);
  ws.send(large);
  ok((await next()) === `echo:${large}`, "a 600 KB message is fragmented and reassembled both ways");
  ws.close();

  const chatOnly = await pairBrowser(false);
  const denied = await fetch(`${BASE}/`, { headers: { cookie: chatOnly.cookie, accept: "text/html" } });
  ok(denied.status === 403, "a device without web_ui cannot open the UI");
  const noCookie = await fetch(`${BASE}/api/echo`, { method: "POST", body: "{}" });
  ok(noCookie.status === 401, "API calls without a session never reach the phone");

  // ---------------------------------------------------------------- phone goes away
  console.log("offline");
  link.kill();
  await sleep(1500);
  const offline = await fetch(`${BASE}/`, { headers: H({ accept: "text/html" }) });
  ok(offline.status === 503, "with the phone offline the browser is told so (nothing is queued)");

  console.log(`\nall ${passed} checks passed`);
  engine.close();
  process.exit(0);
}

main().catch((e) => {
  console.error(e instanceof Error ? e.message : e);
  process.exit(1);
});
