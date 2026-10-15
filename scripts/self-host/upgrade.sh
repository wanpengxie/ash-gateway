#!/bin/sh
# Upgrades a self-hosted relay to a release published on GitHub, and rolls back when it does not come up.
#
#   upgrade.sh <version>          e.g. upgrade.sh 0.7.1   (as root)
#
# Downloads ash-gateway.mjs and wrangler.jsonc of release v<version> from the release page only, checks them against the
# release's SHA256SUMS, puts them in <root>/releases/<version> with the local config and a link to the claim secret,
# switches <root>/current to it, restarts the service and waits for /v1/health to report <version>. If it does not, the
# previous release is switched back and restarted. The relay's state (--persist-to) is outside the release folders.
#
# Layout (ASH_RELAY_ROOT, default /opt/ash-relay): node_modules/ (wrangler), .dev.vars (BOOTSTRAP_SECRET, 0600),
# releases/<version>/, current -> releases/<version>, bin/upgrade.sh (this script; replaced by the release's own copy).
# Proxies: curl honours HTTPS_PROXY / NO_PROXY.
set -eu

version=${1:?usage: upgrade.sh <version>}
version=${version#v}
case "$version" in *[!0-9.]*|'') echo "not a version: $version" >&2; exit 2;; esac
root=${ASH_RELAY_ROOT:-/opt/ash-relay}
service=${ASH_RELAY_SERVICE:-ash-relay}
port=${ASH_RELAY_PORT:-8787}
repo=${ASH_RELAY_REPO:-wanpengxie/ash-gateway}
# Only GitHub's release pages (the override is for testing this script).
base="${ASH_RELAY_RELEASES:-https://github.com/$repo/releases/download}/v$version"

[ -x "$root/node_modules/.bin/wrangler" ] || { echo "wrangler is not installed in $root/node_modules (npm install --prefix $root wrangler@4)" >&2; exit 1; }
[ -f "$root/.dev.vars" ] || { echo "$root/.dev.vars (BOOTSTRAP_SECRET=...) is missing" >&2; exit 1; }
mkdir -p "$root/releases"
current=$(readlink "$root/current" 2>/dev/null || true)
if [ "$current" = "releases/$version" ] && [ "${ASH_RELAY_FORCE:-}" != 1 ]; then echo "already on $version"; exit 0; fi

stage=$(mktemp -d "$root/releases/.stage-XXXXXX")
trap 'rm -rf "$stage"' EXIT
chmod 755 "$stage"
echo "downloading release v$version from $base"
for f in SHA256SUMS ash-gateway.mjs wrangler.jsonc upgrade.sh; do
  curl --proto '=https' --tlsv1.2 -fsSL --retry 2 --connect-timeout 20 -o "$stage/$f" "$base/$f" || { echo "cannot download $f of v$version; nothing changed" >&2; exit 1; }
done
# Every file is checked against the release's own list; one that is not in it, or does not match, stops here.
for f in ash-gateway.mjs wrangler.jsonc upgrade.sh; do
  want=$(awk -v f="$f" '$2 == f || $2 == "*" f { print $1 }' "$stage/SHA256SUMS")
  got=$(sha256sum "$stage/$f" | awk '{ print $1 }')
  [ -n "$want" ] && [ "$want" = "$got" ] || { echo "checksum failed for $f; nothing changed" >&2; exit 1; }
done

# The local config: the release's, without routes (with a custom domain wrangler dev rewrites the Host, and every signed
# claim and sign-in fails) and without workers.dev. The worker's name stays ash-gateway: the stored state is kept under it.
node -e '
  const fs = require("node:fs");
  const c = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (c.name !== "ash-gateway") console.error(`the release names the worker ${c.name}; ash-gateway is kept so the stored state is found`);
  delete c.routes; c.name = "ash-gateway"; c.workers_dev = false;
  fs.writeFileSync(process.argv[2], JSON.stringify(c, null, 2) + "\n");
' "$stage/wrangler.jsonc" "$stage/wrangler.local.jsonc"
ln -s ../../.dev.vars "$stage/.dev.vars"
chmod 755 "$stage/upgrade.sh"

dir="$root/releases/$version"
rm -rf "$dir.old"; [ -e "$dir" ] && mv "$dir" "$dir.old"
mv "$stage" "$dir"
trap - EXIT
rm -rf "$dir.old"

switch() { ln -sfn "$1" "$root/current.new" && mv -T "$root/current.new" "$root/current"; }
healthy() {
  i=0
  while [ $i -lt 90 ]; do
    if curl -fsS --max-time 5 "http://127.0.0.1:$port/v1/health" 2>/dev/null | grep -q "\"version\":\"$1\""; then return 0; fi
    i=$((i + 3)); sleep 3
  done
  return 1
}

echo "switching to $version (was ${current:-none})"
switch "releases/$version"
systemctl restart "$service"
if healthy "$version"; then
  install -m 755 "$dir/upgrade.sh" "$root/bin/upgrade.sh" 2>/dev/null || { mkdir -p "$root/bin" && install -m 755 "$dir/upgrade.sh" "$root/bin/upgrade.sh"; }
  # Keep the three newest releases.
  ls -1t "$root/releases" | grep -E '^[0-9.]+$' | tail -n +4 | while read -r old; do [ "releases/$old" = "releases/$version" ] || rm -rf "$root/releases/$old"; done
  echo "relay $version is up"
  exit 0
fi

echo "relay $version did not come up within 90 s" >&2
if [ -n "$current" ] && [ -d "$root/$current" ]; then
  echo "rolling back to ${current#releases/}" >&2
  switch "$current"
  rm -rf "$dir"
  systemctl restart "$service"
  if healthy "${current#releases/}"; then echo "rolled back to ${current#releases/}" >&2; else echo "the previous release did not come up either: look at journalctl -u $service" >&2; fi
fi
exit 1
