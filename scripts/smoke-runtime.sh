#!/bin/sh
set -eu
binary=$1
root=$(mktemp -d /tmp/cwr-runtime.XXXXXX)
pid=
cleanup() {
  if [ -n "$pid" ]; then
    kill "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
  rm -rf "$root"
}
trap cleanup EXIT HUP INT TERM
cli() { "$binary" --data-dir "$root/state" --json "$@"; }
"$binary" --version
cli init-ip --ip 127.0.0.1 --port 18443 --listen 127.0.0.1:18443 >/dev/null
"$binary" --data-dir "$root/state" --json serve >"$root/service.log" 2>&1 &
pid=$!
attempt=0
until cli status >"$root/status.json" 2>/dev/null; do
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 20 ] || ! kill -0 "$pid" 2>/dev/null; then
    cat "$root/service.log" >&2
    exit 1
  fi
  sleep 0.1
done
grep -q 'cowork.relay/1' "$root/status.json"
cli devices add-host --name synthetic-host --group synthetic \
  --credential-out "$root/computer.json" >/dev/null
test -s "$root/computer.json"
cli devices list >"$root/devices.json"
grep -q 'synthetic-host' "$root/devices.json"
cli trust-export --out "$root/trust.json" >/dev/null
test -s "$root/trust.json"
kill "$pid"
wait "$pid"
pid=
cli renew-ip >/dev/null
echo 'Runtime smoke passed: init, serve, private CLI, registration, trust, renewal'
