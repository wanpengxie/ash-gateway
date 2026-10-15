// Public entry: routing, basic request hygiene, then hand the API to the single
// GatewayHub Durable Object. The Worker keeps no state.
//
// The gateway is a channel only: it claims, authenticates, registers pairings, routes and
// relays. It serves no page and no content; every path outside /v1/ is 404.

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
    if (!url.pathname.startsWith("/v1/")) return json(404, { error: "not_found" });

    // Native clients send no Origin; a browser would, on cross-site POST and WebSocket requests.
    // A foreign Origin is refused before anything reaches the hub. This is a CSRF guard only —
    // every state change is still signature-checked.
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
