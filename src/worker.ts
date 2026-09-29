// Public entry: routing, basic request hygiene, then hand everything to the
// single GatewayHub Durable Object. The Worker keeps no state.

import type { Env } from "./env";
import { json } from "./http";
import { GatewayHub } from "./hub";
import { LIMITS } from "./protocol";
import { ICON_SVG, WEB_MANIFEST } from "./static";

export { GatewayHub };

/** Headers only the Worker may set on requests to the hub; client copies are dropped. */
const INTERNAL_HEADERS = ["x-ash-origin"];

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    // The web app manifest and its icon are public and cached at the edge: browsers fetch them
    // without cookies (install prompts, the pairing page), and they carry nothing private.
    if (request.method === "GET" && url.pathname === "/manifest.webmanifest") return staticAsset(WEB_MANIFEST, "application/manifest+json");
    if (request.method === "GET" && url.pathname === "/icon.svg") return staticAsset(ICON_SVG, "image/svg+xml");

    // /v1/* is the gateway API; every other path is the phone's ash UI through the tunnel
    // (the hub answers with the pairing page until this browser is a paired device).
    const api = url.pathname.startsWith("/v1/");

    // Browsers always send Origin on cross-site POST and WebSocket requests; native
    // clients send none. A foreign Origin is refused before anything reaches the hub.
    // This is a CSRF guard only — every state change is still signature-checked.
    const origin = request.headers.get("origin");
    if (origin !== null && origin !== url.origin) return json(403, { error: "origin_not_allowed" });

    const length = Number(request.headers.get("content-length") ?? "0");
    if (length > (api ? LIMITS.maxBodyBytes : LIMITS.webMaxBodyBytes)) return json(413, { error: "body_too_large" });

    const headers = new Headers(request.headers);
    for (const h of INTERNAL_HEADERS) headers.delete(h);
    headers.set("x-ash-origin", url.origin);

    // V1: one deployment serves one Agent phone, so one hub instance.
    // The object name is routing, not a credential.
    const hub = env.HUB.get(env.HUB.idFromName("hub"));
    return hub.fetch(new Request(request, { headers }));
  },
} satisfies ExportedHandler<Env>;

function staticAsset(body: string, type: string): Response {
  return new Response(body, { headers: { "content-type": type, "cache-control": "public, max-age=86400, immutable" } });
}
