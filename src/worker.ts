// Public entry: routing, basic request hygiene, then hand everything to the
// single GatewayHub Durable Object. The Worker keeps no state.

import type { Env } from "./env";
import { json } from "./http";
import { GatewayHub } from "./hub";
import { LIMITS } from "./protocol";

export { GatewayHub };

/** Headers only the Worker may set on requests to the hub; client copies are dropped. */
const INTERNAL_HEADERS = ["x-ash-origin"];

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/" && request.method === "GET") return landing(url.origin);
    if (!url.pathname.startsWith("/v1/")) return json(404, { error: "not_found" });

    // Browsers always send Origin on cross-site POST and WebSocket requests; native
    // clients send none. A foreign Origin is refused before anything reaches the hub.
    // This is a CSRF guard only — every state change is still signature-checked.
    const origin = request.headers.get("origin");
    if (origin !== null && origin !== url.origin) return json(403, { error: "origin_not_allowed" });

    const length = Number(request.headers.get("content-length") ?? "0");
    if (length > LIMITS.maxBodyBytes) return json(413, { error: "body_too_large" });

    const headers = new Headers(request.headers);
    for (const h of INTERNAL_HEADERS) headers.delete(h);
    headers.set("x-ash-origin", url.origin);

    // V1: one deployment serves one Agent phone, so one hub instance.
    // The object name is routing, not a credential.
    const hub = env.HUB.get(env.HUB.idFromName("hub"));
    return hub.fetch(new Request(request, { headers }));
  },
} satisfies ExportedHandler<Env>;

function landing(origin: string): Response {
  const body = `<!doctype html><meta charset="utf-8"><title>ash gateway</title>
<style>body{font:15px/1.6 system-ui,sans-serif;max-width:40rem;margin:3rem auto;padding:0 1rem;color:#222}</style>
<h1>ash gateway</h1>
<p>This is a self-hosted relay for an <a href="https://github.com/wanpengxie/ash-gateway">ash</a> personal agent phone.
It stores no conversations, memory or files.</p>
<p>Gateway URL for the app: <code>${origin}</code></p>
<p>Status: <a href="/v1/health">/v1/health</a></p>`;
  return new Response(body, { headers: { "content-type": "text/html; charset=utf-8" } });
}
