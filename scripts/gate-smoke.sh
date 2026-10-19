#!/usr/bin/env bash
# The gate's check from a visitor's side (plan 20261019-proxy-gate, AC9): a cold visit to a page of a
# host — no cookie — gets exactly one x-api-token cookie, and every <img src="/api/…pics…"> of the
# page loads with it (200). Run against a host in enforce, or against a stand:
#
#   scripts/gate-smoke.sh https://cars.koreaautotrade.pro /ru/catalog
#   scripts/gate-smoke.sh --stand 3000 group.json /ru/catalog
#
# --stand runs boks's proxy image (BOKS_CADDY_IMAGE, boks-caddy:test by default — `docker build -t
# boks-caddy:test proxy`) on localhost:$STAND_PORT (8080 by default) in front of a site's `next start` on the given port of this
# machine, with the boks_gate handler of group.json (a group as the policy gives it, its secrets in place
# of secret_env) on every request. CURL_OPTS passes options to curl, such as a SOCKS proxy for a
# host reachable only from another zone: CURL_OPTS="--socks5-hostname 127.0.0.1:18181".
set -euo pipefail

stand="" dir="" jar=$(mktemp) html=$(mktemp)
cleanup() {
	rm -f "$jar" "$html"
	if [ -n "$dir" ]; then
		docker rm -f boks-gate-stand >/dev/null 2>&1 || true
		rm -f "$dir/caddy.json"
		rmdir "$dir"
	fi
}
trap cleanup EXIT
if [ "${1:-}" = "--stand" ]; then
	site_port=$2 group=$3
	shift 3
	image=${BOKS_CADDY_IMAGE:-boks-caddy:test} port=${STAND_PORT:-8080}
	dir=$(mktemp -d)
	jq -n --slurpfile g "$group" --arg up "host.docker.internal:$site_port" '{
		admin: {disabled: true},
		apps: {http: {servers: {stand: {listen: [":8080"], logs: {}, routes: [
			{handle: [($g[0] + {handler: "boks_gate"})]},
			{handle: [{handler: "reverse_proxy", upstreams: [{dial: $up}]}]}
		]}}}}}' > "$dir/caddy.json"
	docker run -d --name boks-gate-stand -p "$port:8080" --add-host host.docker.internal:host-gateway \
		-v "$dir:/etc/stand:ro" "$image" caddy run --config /etc/stand/caddy.json >/dev/null
	for _ in $(seq 50); do curl -fs -o /dev/null "http://localhost:$port/" && break || sleep 0.2; done
	stand="http://localhost:$port"
fi

base=${stand:-${1:?usage: gate-smoke.sh <base-url> [page] | --stand <site-port> <group.json> [page]}}
[ -n "$stand" ] || shift
page=${1:-/}
read -r -a opts <<<"${CURL_OPTS:-}"
headers=$(curl -s ${opts[@]+"${opts[@]}"} -c "$jar" -o "$html" -D - "$base$page")
cookies=$(grep -ci '^set-cookie: x-api-token=' <<<"$headers" || true)
echo "page $page: $(head -1 <<<"$headers" | tr -d '\r'), x-api-token cookies: $cookies"
fail=0
if [ "$cookies" != 1 ]; then
	echo "FAIL: a cold visit gets $cookies x-api-token cookies, want 1"
	fail=1
fi

# Not mapfile: macOS's /bin/bash is 3.2.
pics=$(grep -oE 'src="/api/[^"]*pics[^"]*"' "$html" | sed -e 's/^src="//' -e 's/"$//' -e 's/&amp;/\&/g' | sort -u || true)
echo "images under /api/ on the page: $(grep -c . <<<"$pics" || true)"
while read -r p; do
	[ -n "$p" ] || continue
	code=$(curl -s ${opts[@]+"${opts[@]}"} -b "$jar" -o /dev/null -w '%{http_code}' -H 'Sec-Fetch-Dest: image' "$base$p")
	if [ "$code" != 200 ]; then
		echo "FAIL: $code $p"
		fail=1
	fi
done <<<"$pics"
[ "$fail" = 0 ] && echo "ok: one cookie, every image 200"
exit "$fail"
