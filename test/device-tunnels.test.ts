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
  const open = () => router.fromOwner({ t: "tun", op: "ws.open", sid, to: "pc", path: "/ash/device/stream" }, "phone");
  return { db, router, make, owner, device, open };
}
test("device stream routes both directions and stamps identities", () => {
  const h = setup(); h.open();
  h.router.fromDevice({ op: "ws.msg", sid, text: "up", from: "fake" }, "pc");
  assert.equal(h.owner.at(-1)?.from, "pc");
  h.router.fromOwner({ op: "ws.msg", sid, to: "pc", text: "down" }, "phone");
  assert.equal(h.device.at(-1)?.frame.from, "phone"); h.db.close();
});
test("other device cannot inject into registered HTTP or WS sid", () => {
  const h = setup(); h.open();
  h.router.fromDevice({ op: "ws.msg", sid, text: "spoof" }, "other");
  assert.equal(h.owner.length, 0); assert.equal(h.device.at(-1)?.frame.code, 4403);
  h.router.fromOwner({ op: "http.req", sid: "http1", to: "pc" }, "phone");
  h.router.fromDevice({ op: "http.body", sid: "http1", data: "x" }, "other");
  assert.equal(h.owner.length, 0);
  h.router.fromDevice({ op: "http.req", sid: "http1" }, "pc");
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
  h.router.fromOwner({ op: "ws.open", sid: next, to: "pc", path: "/ash/device/stream" }, "phone");
  assert.equal(h.owner.at(-1)?.code, 4409);
  h.router.disconnect("pc", 4003, "revoked");
  assert.equal(h.owner.at(-1)?.code, 4003); assert.equal(h.device.at(-1)?.frame.code, 4003);
  h.router.fromDevice({ op: "ws.msg", sid: next, text: "late" }, "pc");
  assert.notEqual(h.owner.at(-1)?.text, "late"); h.db.close();
});
test("offline and overlarge frames fail without forwarding data", () => {
  const h = setup();
  h.router.fromOwner({ op: "ws.open", sid, to: "offline", path: "/ash/device/stream" }, "phone");
  assert.equal(h.owner.at(-1)?.code, 4404);
  h.open(); h.router.fromDevice({ op: "ws.msg", sid, text: "中".repeat(100_000) }, "pc");
  assert.equal(h.owner.at(-1)?.code, 4400); h.db.close();
});
test("HTTP registration is removed on completion and expiry", () => {
  const h = setup(); h.router.fromOwner({ op: "http.req", sid: "h", to: "pc" }, "phone");
  h.router.fromDevice({ op: "http.end", sid: "h" }, "pc");
  h.router.fromDevice({ op: "http.body", sid: "h", data: "late" }, "pc");
  assert.equal(h.owner.length, 1);
  h.router.fromOwner({ op: "http.req", sid: "h2", to: "pc" }, "phone");
  h.db.prepare("UPDATE device_tunnels SET expires=0").run();
  h.router.fromDevice({ op: "http.end", sid: "h2" }, "pc");
  assert.equal(h.owner.length, 1); h.db.close();
});
test("stream fragments unicode and binary without corruption", () => {
  let got: string | Uint8Array | undefined;
  const receiver = new DeviceStream(sid, "phone", "/ash/device/stream", () => {}, () => {});
  receiver.onMessage(m => got = m);
  const sender = new DeviceStream(sid, "pc", "/ash/device/stream", f => receiver.accept(f), () => {});
  const text = "a" + "🚀你好".repeat(140_000);
  sender.send(text); assert.equal(got, text);
  const bytes = new Uint8Array(300_001).fill(128); sender.send(bytes); assert.deepEqual(got, bytes);
  sender.send(""); assert.equal(got, "");
});
test("stream bounds fragmented input, closes once, refuses sends after close", () => {
  let closed = 0;
  const stream = new DeviceStream(sid, "pc", "/ash/device/stream", () => {}, () => {});
  stream.onClose(() => closed++);
  for (let n = 0; n < 18; n++) stream.accept({ op: "ws.msg", text: "a".repeat(256 * 1024), more: true });
  assert.equal(closed, 1); assert.throws(() => stream.send("x"), /closed/);
});
