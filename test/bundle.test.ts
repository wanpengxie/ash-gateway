import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DEFAULT_INSTALL_SCRIPT_URL } from "../src/install-page";
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
  assert.deepEqual(meta.compatibility_flags, wrangler.compatibility_flags);
  assert.deepEqual(meta.bindings, [
    ...wrangler.durable_objects.bindings.map((b: { name: string; class_name: string }) => ({ type: "durable_object_namespace", ...b })),
    ...Object.entries(wrangler.vars as Record<string, string>).map(([name, text]) => ({ type: "plain_text", name, text })),
  ]);
  assert.equal(wrangler.vars.INSTALL_SCRIPT_URL, DEFAULT_INSTALL_SCRIPT_URL);
  assert.deepEqual(meta.migrations, { new_tag: wrangler.migrations[0].tag, new_sqlite_classes: wrangler.migrations[0].new_sqlite_classes });
  assert.deepEqual(meta, JSON.parse(JSON.stringify(WORKER_METADATA)));
});
