import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { buildBundle, WORKER_METADATA } from "../scripts/build-bundle";

test("the relay bundle is one module with the worker and Durable Object exports, matching wrangler.jsonc", async () => {
  const out = mkdtempSync(join(tmpdir(), "ash-bundle-"));
  const r = await buildBundle(out);
  const code = readFileSync(r.file, "utf8");
  assert.match(code, /export\s*\{[^}]*\bGatewayHub\b[^}]*\bdefault\b|export\s*\{[^}]*\bdefault\b[^}]*\bGatewayHub\b/);
  const imports = [...code.matchAll(/from\s*"([^"]+)"|import\s*"([^"]+)"/g)].map(m => m[1] ?? m[2]);
  assert.ok(imports.every(i => i.startsWith("cloudflare:")), `only runtime imports remain: ${imports}`);
  assert.ok(r.bytes < 1_000_000);
  const meta = JSON.parse(readFileSync(r.metadata, "utf8"));
  assert.equal(meta.main_module, "ash-gateway.mjs");
  const wrangler = JSON.parse(readFileSync(join(import.meta.dirname, "../wrangler.jsonc"), "utf8").split("\n").filter(l => !/^\s*\/\//.test(l)).join("\n"));
  assert.equal(meta.compatibility_date, wrangler.compatibility_date);
  assert.equal(meta.compatibility_flags, wrangler.compatibility_flags);
  assert.deepEqual(meta.bindings, wrangler.durable_objects.bindings.map((b: { name: string; class_name: string }) => ({ type: "durable_object_namespace", ...b })));
  assert.equal(wrangler.vars, undefined, "no variables: the relay serves no page that would need one");
  assert.deepEqual(meta.migrations, { new_tag: wrangler.migrations[0].tag, new_sqlite_classes: wrangler.migrations[0].new_sqlite_classes });
  assert.deepEqual(meta, JSON.parse(JSON.stringify(WORKER_METADATA)));
});

test("a release lists every file it publishes in SHA256SUMS, upgrade.sh among them", async () => {
  const out = mkdtempSync(join(tmpdir(), "ash-bundle-"));
  await buildBundle(out);
  const lines = readFileSync(join(out, "SHA256SUMS"), "utf8").trim().split("\n").map((l) => l.split("  "));
  assert.deepEqual(lines.map(([, name]) => name), ["ash-gateway.mjs", "ash-gateway.metadata.json", "wrangler.jsonc", "upgrade.sh"]);
  for (const [sha, name] of lines) assert.equal(sha, createHash("sha256").update(readFileSync(join(out, name!))).digest("hex"), name);
  assert.equal(readFileSync(join(out, "upgrade.sh"), "utf8"), readFileSync(join(import.meta.dirname, "../scripts/self-host/upgrade.sh"), "utf8"));
});

test("the version /v1/health reports is the package's: a self-hosted upgrade waits for it", () => {
  const pkg = JSON.parse(readFileSync(join(import.meta.dirname, "../package.json"), "utf8")) as { version: string };
  const hub = readFileSync(join(import.meta.dirname, "../src/hub.ts"), "utf8");
  assert.equal(/export const GATEWAY_VERSION = "([^"]+)"/.exec(hub)?.[1], pkg.version);
});
