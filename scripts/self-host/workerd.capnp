@0xcbead598b75e4f97;
using Workerd = import "/workerd/workerd.capnp";

# The namespace and disk layout deliberately match the former Miniflare deployment.
# Keep both stable: changing them would make a claimed relay look empty.
const config :Workerd.Config = (
  services = [
    (name = "relay", worker = (
      modules = [(name = "ash-gateway.mjs", esModule = embed "ash-gateway.mjs")],
      compatibilityDate = "2026-09-01",
      bindings = [
        (name = "HUB", durableObjectNamespace = "GatewayHub"),
        (name = "BOOTSTRAP_SECRET", fromEnvironment = "BOOTSTRAP_SECRET"),
        (name = "RESET_EPOCH", fromEnvironment = "RESET_EPOCH")
      ],
      durableObjectNamespaces = [
        (className = "GatewayHub", uniqueKey = "ash-gateway-GatewayHub", enableSql = true)
      ],
      durableObjectStorage = (localDisk = "storage")
    )),
    (name = "storage", disk = (path = "/var/lib/ash-relay/v3/do", writable = true))
  ],
  sockets = [(name = "http", address = "127.0.0.1:8787",
    http = (forwardedProtoHeader = "X-Forwarded-Proto"), service = "relay")]
);
