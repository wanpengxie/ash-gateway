// Builds the relay as one ES module file plus the upload metadata, for the hub's one-tap relay
// setup (Cloudflare "upload worker module" API). Nothing here talks to Cloudflare.
//
//   npm run build:bundle  ->  dist/ash-gateway.mjs, dist/ash-gateway.metadata.json
//
// The metadata is the multipart `metadata` part of the upload. The deployer adds the account-specific
// bindings (for example the BOOTSTRAP_SECRET `secret_text`) before sending.
import { build } from "esbuild";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { DEFAULT_INSTALL_SCRIPT_URL } from "../src/install-page";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");

/** Keep in step with wrangler.jsonc (compatibility date and flags, the HUB binding, vars, migration v1). */
export const WORKER_METADATA = {
  main_module: "ash-gateway.mjs",
  compatibility_date: "2026-09-01",
  compatibility_flags: ["enable_request_signal"],
  bindings: [
    { type: "durable_object_namespace", name: "HUB", class_name: "GatewayHub" },
    // Default installer address for the install page; a deployer replaces the text to point elsewhere.
    { type: "plain_text", name: "INSTALL_SCRIPT_URL", text: DEFAULT_INSTALL_SCRIPT_URL },
  ],
  migrations: { new_tag: "v1", new_sqlite_classes: ["GatewayHub"] },
  // A redeploy keeps variables set in the dashboard (RESET_EPOCH) and the claim secret.
  keep_bindings: ["plain_text", "secret_text"],
  observability: { enabled: true },
} as const;

export async function buildBundle(outDir = join(root, "dist")): Promise<{ file: string; metadata: string; sha256: string; bytes: number }> {
  mkdirSync(outDir, { recursive: true });
  const file = join(outDir, "ash-gateway.mjs");
  await build({
    entryPoints: [join(root, "src/worker.ts")],
    outfile: file,
    bundle: true,
    format: "esm",
    platform: "neutral",
    target: "es2022",
    mainFields: ["module", "main"],
    conditions: ["workerd", "worker", "browser"],
    external: ["cloudflare:*"],
    minify: true,
    legalComments: "none",
    logLevel: "warning",
  });
  const metadata = join(outDir, "ash-gateway.metadata.json");
  writeFileSync(metadata, JSON.stringify(WORKER_METADATA, null, 2) + "\n");
  const data = readFileSync(file);
  const sha256 = createHash("sha256").update(data).digest("hex");
  writeFileSync(join(outDir, "ash-gateway.mjs.sha256"), `${sha256}  ash-gateway.mjs\n`);
  return { file, metadata, sha256, bytes: data.length };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const r = await buildBundle();
  console.log(`${r.file}\n${r.metadata}\nsha256 ${r.sha256} (${r.bytes} bytes)`);
}
