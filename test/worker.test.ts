import { test } from "node:test";
import assert from "node:assert/strict";
import { register } from "node:module";

// The Worker imports the Durable Object class, which needs the runtime's module: a stub is enough here.
register("data:text/javascript," + encodeURIComponent(
  `export async function resolve(s, c, next) { return s === "cloudflare:workers" ? { url: "data:text/javascript,export class DurableObject {}", shortCircuit: true } : next(s, c); }`,
));
const { default: worker } = await import("../src/worker");

/** An env whose hub records what reached it. */
function env() {
  const reached: Request[] = [];
  const hub = { fetch: async (r: Request) => { reached.push(r); return new Response("hub"); } };
  return { reached, value: { HUB: { idFromName: () => "hub", get: () => hub } } as never };
}

test("the relay serves no page or content: every path outside /v1/ is 404 and never reaches the hub", async () => {
  const e = env();
  for (const path of ["/", "/p/abc123", "/p/", "/manifest.webmanifest", "/icon.svg", "/index.html", "/api/send", "/link", "/v1", "/V1/health"]) {
    for (const method of ["GET", "POST"]) {
      const res = await worker.fetch(new Request(`https://relay.example${path}`, { method, headers: { accept: "text/html" } }), e.value);
      assert.equal(res.status, 404, `${method} ${path}`);
      assert.match(res.headers.get("content-type") ?? "", /^application\/json/, `${method} ${path} is not a page`);
    }
  }
  assert.equal(e.reached.length, 0);
});

test("the API goes to the hub, with the origin set by the Worker; a foreign Origin and a large body are refused", async () => {
  const e = env();
  const ok = await worker.fetch(new Request("https://relay.example/v1/health", { headers: { "x-ash-origin": "https://forged.example" } }), e.value);
  assert.equal(await ok.text(), "hub");
  assert.equal(e.reached[0]!.headers.get("x-ash-origin"), "https://relay.example");
  const foreign = await worker.fetch(new Request("https://relay.example/v1/auth/challenge", { method: "POST", headers: { origin: "https://evil.example" }, body: "{}" }), e.value);
  assert.equal(foreign.status, 403);
  const big = await worker.fetch(new Request("https://relay.example/v1/pair/request", { method: "POST", headers: { "content-length": String(17 * 1024) }, body: "x".repeat(17 * 1024) }), e.value);
  assert.equal(big.status, 413);
  assert.equal(e.reached.length, 1);
});
