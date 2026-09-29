import assert from "node:assert/strict";
import { createSign, generateKeyPairSync } from "node:crypto";
import { test } from "node:test";
import { DeviceKey, GatewayClient } from "../client/client";
import { b64u, ctx, deviceIdForKey, derToRaw, fromB64u, hmacSha256, signingInput, timingSafeEqual, verifySignature } from "../src/protocol";

test("signing input is the fixed line format", () => {
  const bytes = signingInput("auth", ["https://gw.example", "dev1", "n0nce"]);
  assert.equal(new TextDecoder().decode(bytes), "ash-gw/1\nauth\nhttps://gw.example\ndev1\nn0nce");
});

test("fields with line breaks are refused", () => {
  assert.throws(() => signingInput("auth", ["a\nb"]));
});

test("pair approval sorts permissions so both sides agree", () => {
  const a = ctx.pairApprove("o", "r", "c", "k", ["read_status", "chat"], 3);
  const b = ctx.pairApprove("o", "r", "c", "k", ["chat", "read_status"], 3);
  assert.deepEqual(a, b);
});

test("base64url round trip", () => {
  const raw = crypto.getRandomValues(new Uint8Array(37));
  assert.deepEqual(fromB64u(b64u(raw)), raw);
});

test("WebCrypto raw signatures verify", async () => {
  const k = await DeviceKey.generate();
  const data = ctx.auth("o", k.id, "n");
  assert.ok(await verifySignature(k.publicKey, await k.sign(data), data));
  assert.ok(!(await verifySignature(k.publicKey, await k.sign(data), ctx.auth("o", k.id, "other"))));
});

test("DER signatures (Android SHA256withECDSA) verify", async () => {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const spki = b64u(new Uint8Array(publicKey.export({ type: "spki", format: "der" })));
  const data = ctx.auth("https://gw.example", await deviceIdForKey(spki), "n");
  for (let i = 0; i < 20; i++) {
    const der = createSign("SHA256").update(data).sign(privateKey); // DER by default
    assert.ok(derToRaw(new Uint8Array(der)));
    assert.ok(await verifySignature(spki, b64u(new Uint8Array(der)), data));
  }
});

test("device id is stable and derived from the key", async () => {
  const k = await DeviceKey.generate();
  assert.equal(await deviceIdForKey(k.publicKey), k.id);
  assert.equal(k.id.length, 22);
});

test("envelope signature covers the payload bytes", async () => {
  const k = await DeviceKey.generate();
  const c = new GatewayClient("https://gw.example", k);
  const e = await c.envelope("agent.message", "owner", { text: "hi" });
  assert.ok(await GatewayClient.verifyEnvelope(e, k.publicKey));
  assert.ok(!(await GatewayClient.verifyEnvelope({ ...e, payload: '{"text":"hj"}' }, k.publicKey)));
  assert.ok(!(await GatewayClient.verifyEnvelope({ ...e, to: "someone" }, k.publicKey)));
});

test("hmac and constant-time compare", async () => {
  const m = await hmacSha256("secret", new TextEncoder().encode("x"));
  assert.ok(timingSafeEqual(m, await hmacSha256("secret", new TextEncoder().encode("x"))));
  assert.ok(!timingSafeEqual(m, await hmacSha256("secreT", new TextEncoder().encode("x"))));
});
