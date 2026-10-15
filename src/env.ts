import type { GatewayHub } from "./hub";

export interface Env {
  HUB: DurableObjectNamespace<GatewayHub>;
  /** One-time claim secret (Worker Secret). Unset → claiming is refused, never anonymous. */
  BOOTSTRAP_SECRET?: string;
  /** Changing this value from the Cloudflare account wipes the gateway (lost-phone reset). */
  RESET_EPOCH?: string;
}
