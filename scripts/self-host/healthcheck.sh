#!/bin/sh
# A memory-reclaim stall need not cause an OOM kill. Bound the HTTP wait and restart the whole unit.
set -eu
service=${ASH_RELAY_SERVICE:-ash-relay}
port=${ASH_RELAY_PORT:-8787}
ctl=${ASH_RELAY_SYSTEMCTL:-systemctl}
"$ctl" is-active --quiet "$service" || exit 0
healthy() { curl -fsS --max-time 5 "http://127.0.0.1:$port/v1/health" 2>/dev/null | grep -q '"ok":true'; }
healthy && exit 0
sleep 2
healthy && exit 0
echo "relay health request failed twice; restarting $service" >&2
"$ctl" restart "$service"
