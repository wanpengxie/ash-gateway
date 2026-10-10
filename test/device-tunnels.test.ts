import { test } from "node:test";
import assert from "node:assert/strict";
import { DatabaseSync } from "node:sqlite";
import { DeviceTunnels, type TunnelSql } from "../src/device-tunnels";
import { DeviceStream } from "../client/stream";
type Frame = Record<string, unknown>;
const sid = "o-1234567890123456789012";
function setup() {
  const db = new DatabaseSync(":memory:");
  const sql: TunnelSql = { exec<T>(q: string, ...args: (string | number)[]) {
    const stmt = db.prepare(q);
    if (/^SELECT/.test(q)) return { toArray: () => stmt.all(...args) as T[] };
    stmt.run(...args); return { toArray: () => [] as T[] };
  } };
  const owner: Frame[] = [], device: { id: string; frame: Frame }[] = [];
  const make = () => new DeviceTunnels(sql, f => owner.push(f), (id, frame) => device.push({ id, frame }), id => ["pc", "other"].includes(id));
  const router = make();
  const open = () => router.fromOwner({ t: "tun", op: "ws.open", sid, to: "pc", path: "/link" }, "phone");
  return { db, router, make, owner, device, open };
}
test("device stream routes both directions and stamps identities", () => {
  const h = setup(); h.open();
  h.router.fromDevice({ op: "ws.msg", sid, text: "up", from: "fake" }, "pc");
  assert.equal(h.owner.at(-1)?.from, "pc");
  h.router.fromOwner({ op: "ws.msg", sid, to: "pc", text: "down" }, "phone");
  assert.equal(h.device.at(-1)?.frame.from, "phone"); h.db.close();
});
test("other device cannot inject into registered WS sid", () => {
  const h = setup(); h.open();
  h.router.fromDevice({ op: "ws.msg", sid, text: "spoof" }, "other");
  assert.equal(h.owner.length, 0); assert.equal(h.device.at(-1)?.frame.code, 4403);
  h.router.fromDevice({ op: "ws.close", sid, code: 1000 }, "other");
  assert.equal(h.owner.length, 0);
  h.router.fromDevice({ op: "http.head", sid, status: 200 }, "pc");
  assert.equal(h.owner.length, 0); h.db.close();
});
test("tunnel registration survives constructing a new router", () => {
  const h = setup(); h.open();
  h.make().fromDevice({ op: "ws.msg", sid, text: "after hibernation" }, "pc");
  assert.equal(h.owner.at(-1)?.text, "after hibernation"); h.db.close();
});
test("new stream replaces previous one and disconnect closes both ends", () => {
  const h = setup(); h.open();
  const next = sid + "n";
  h.router.fromOwner({ op: "ws.open", sid: next, to: "pc", path: "/link" }, "phone");
  assert.equal(h.owner.at(-1)?.code, 4409);
  h.router.disconnect("pc", 4003, "revoked");
  assert.equal(h.owner.at(-1)?.code, 4003); assert.equal(h.device.at(-1)?.frame.code, 4003);
  h.router.fromDevice({ op: "ws.msg", sid: next, text: "late" }, "pc");
  assert.notEqual(h.owner.at(-1)?.text, "late"); h.db.close();
});
test("offline and overlarge frames fail without forwarding data", () => {
  const h = setup();
  h.router.fromOwner({ op: "ws.open", sid, to: "offline", path: "/link" }, "phone");
  assert.equal(h.owner.at(-1)?.code, 4404);
  h.open(); h.router.fromDevice({ op: "ws.msg", sid, text: "中".repeat(100_000) }, "pc");
  assert.equal(h.owner.at(-1)?.code, 4400); h.db.close();
});
test("only /link is accepted; the old paths and any other path are refused without registering", () => {
  const h = setup();
  h.open();
  assert.deepEqual(h.device.at(-1)?.frame, { t: "tun", op: "ws.open", sid, to: "pc", path: "/link", from: "phone" });
  assert.equal(h.owner.length, 0);
  h.router.fromOwner({ op: "ws.close", sid, to: "pc" }, "phone");
  for (const path of ["/ash/device/stream", "/ash/manifest", "/ash/call", "/ash/update", "/link/", "/link?x=1", "/Link", "/", "", undefined]) {
    const before = h.device.length;
    h.router.fromOwner({ op: "ws.open", sid, to: "pc", path }, "phone");
    assert.equal(h.owner.at(-1)?.code, 4404, String(path));
    assert.equal(h.owner.at(-1)?.reason, "path_not_allowed", String(path));
    assert.equal(h.device.length, before, "nothing reaches the device");
  }
  assert.equal(h.db.prepare("SELECT count(*) AS n FROM device_tunnels").get()?.n, 0);
  h.db.close();
});
test("device HTTP tunnels are gone: every http.* op is refused and nothing is registered", () => {
  const h = setup();
  for (const op of ["http.req", "http.reqbody", "http.reqend", "http.abort"]) {
    h.router.fromOwner({ op, sid: "h", to: "pc", path: "/ash/manifest", method: "GET" }, "phone");
    assert.equal(h.owner.at(-1)?.op, "http.error"); assert.equal(h.owner.at(-1)?.message, "http_tunnel_removed");
  }
  assert.equal(h.device.length, 0);
  assert.equal(h.db.prepare("SELECT count(*) AS n FROM device_tunnels").get()?.n, 0);
  const seen = h.owner.length;
  h.router.fromDevice({ op: "http.head", sid: "h", status: 200 }, "pc");
  h.router.fromDevice({ op: "http.end", sid: "h" }, "pc");
  assert.equal(h.owner.length, seen); h.db.close();
});
test("leftover HTTP rows from an older version are dropped, not served", () => {
  const h = setup();
  h.db.prepare("INSERT INTO device_tunnels (sid,device,kind,expires) VALUES ('old','pc','http',?)").run(Date.now() + 100_000);
  h.router.fromDevice({ op: "http.end", sid: "old" }, "pc");
  assert.equal(h.owner.length, 0); assert.equal(h.device.at(-1)?.frame.op, "error");
  assert.equal(h.db.prepare("SELECT count(*) AS n FROM device_tunnels").get()?.n, 0); h.db.close();
});
test("both ends relay link frames through the tunnel with gateway-stamped identities", () => {
  const h = setup(); h.open();
  // Fake kernel and fake device wired through the router.
  const kernelGot: Frame[] = [], deviceGot: Frame[] = [];
  const pump = () => {
    for (const d of h.device.splice(0)) deviceGot.push(d.frame);
    for (const o of h.owner.splice(0)) kernelGot.push(o);
  };
  h.router.fromDevice({ t: "tun", op: "ws.opened", sid, from: "forged" }, "pc");
  // The device (computer) accepts, the kernel sends the challenge first (SPEC-03 section 2).
  const challenge = JSON.stringify({ t: "challenge", nonce: "n", kernel: { protocol: "ash-link/1" } });
  const hello = JSON.stringify({ t: "hello", protocol: "ash-link/1" });
  h.router.fromOwner({ t: "tun", op: "ws.msg", sid, to: "pc", text: challenge }, "phone");
  h.router.fromDevice({ t: "tun", op: "ws.msg", sid, text: hello, to: "forged" }, "pc");
  pump();
  assert.deepEqual(deviceGot.map(f => [f.op, f.from]), [["ws.open", "phone"], ["ws.msg", "phone"]]);
  assert.equal(deviceGot[1].text, challenge);
  assert.deepEqual(kernelGot.map(f => [f.op, f.from, f.to]), [["ws.opened", "pc", undefined], ["ws.msg", "pc", undefined]]);
  assert.equal(kernelGot[1].text, hello);
  h.router.fromDevice({ t: "tun", op: "ws.close", sid, code: 1000, reason: "bye" }, "pc");
  h.router.fromDevice({ t: "tun", op: "ws.msg", sid, text: "late" }, "pc");
  pump();
  assert.equal(kernelGot.at(-1)?.op, "ws.close"); assert.equal(kernelGot.some(f => f.text === "late"), false);
  h.db.close();
});
test("stream fragments unicode and binary without corruption", () => {
  let got: string | Uint8Array | undefined;
  const receiver = new DeviceStream(sid, "phone", "/link", () => {}, () => {});
  receiver.onMessage(m => got = m);
  const sender = new DeviceStream(sid, "pc", "/link", f => receiver.accept(f), () => {});
  const text = "a" + "🚀你好".repeat(140_000);
  sender.send(text); assert.equal(got, text);
  const bytes = new Uint8Array(300_001).fill(128); sender.send(bytes); assert.deepEqual(got, bytes);
  sender.send(""); assert.equal(got, "");
});
test("stream bounds fragmented input, closes once, refuses sends after close", () => {
  let closed = 0;
  const stream = new DeviceStream(sid, "pc", "/link", () => {}, () => {});
  stream.onClose(() => closed++);
  for (let n = 0; n < 18; n++) stream.accept({ op: "ws.msg", text: "a".repeat(256 * 1024), more: true });
  assert.equal(closed, 1); assert.throws(() => stream.send("x"), /closed/);
});
