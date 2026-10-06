#!/usr/bin/env bash
# Where do the reload errors come from? Same load, four cases:
#  base   — no reloads at all (is it the load generator?)
#  file   — `caddy reload` of the whole file (what failed: 231/61k)
#  patch  — admin API PATCH of only the upstream dial
#  ka     — whole-file reload, but clients keep connections alive
set -euo pipefail
D=/tmp/caddyreload
docker rm -f cr-caddy cr-a cr-b >/dev/null 2>&1 || true
docker network rm cr >/dev/null 2>&1 || true
docker run --rm -v /tmp:/t alpine rm -rf /t/caddyreload
mkdir -p "$D"
docker network create cr >/dev/null
docker run -d --name cr-a --network cr traefik/whoami --name A >/dev/null
docker run -d --name cr-b --network cr traefik/whoami --name B >/dev/null
conf() {
  cat > "$D/caddy.json" <<EOF
{"admin":{"listen":"0.0.0.0:2019"},
 "apps":{"http":{"servers":{"boks":{"listen":[":80"],"routes":[
   {"match":[{"host":["h1.test"]}],"handle":[{"handler":"reverse_proxy","upstreams":[{"dial":"$1:80"}]}],"terminal":true}
 ]}}}}}
EOF
}
conf cr-a
docker run -d --name cr-caddy --network cr -v "$D:/cfg" caddy:2-alpine caddy run --config /cfg/caddy.json >/dev/null
sleep 2
ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "cr").IPAddress}}' cr-caddy)

run() { # $1 case, $2 keepalive flag
  docker run --rm --network cr --add-host h1.test:$ip fortio/fortio load -c 40 -qps 0 -t 20s $2 http://h1.test/ > "$D/$1.txt" 2>&1 &
  local lp=$!
  sleep 3
  for i in $(seq 1 10); do
    up=cr-a; [ $((i % 2)) = 1 ] && up=cr-b
    case $1 in
      file|ka) conf $up; docker exec cr-caddy caddy reload --config /cfg/caddy.json >/dev/null 2>&1 ;;
      patch)   docker exec cr-caddy wget -q -O /dev/null --header 'Content-Type: application/json' \
                 --post-data "\"$up:80\"" "http://127.0.0.1:2019/config/apps/http/servers/boks/routes/0/handle/0/upstreams/0/dial" 2>&1 || echo "patch-fail" ;;
      base)    : ;;
    esac
    sleep 1.4
  done
  wait $lp || true
  printf "%-6s %s | %s\n" "$1" "$(grep -E '^Code' "$D/$1.txt" | tr '\n' ' ')" "$(grep -oE '[0-9.]+ qps' "$D/$1.txt")"
}
run base "-keepalive=false"
run file "-keepalive=false"
run patch "-keepalive=false"
run ka ""
echo "== caddy log lines mentioning errors/stopping (last run)"
docker logs cr-caddy 2>&1 | grep -oE '"msg":"[^"]+"' | sort | uniq -c | sort -rn | head -8

docker rm -f cr-caddy cr-a cr-b >/dev/null
docker network rm cr >/dev/null
docker run --rm -v /tmp:/t alpine rm -rf /t/caddyreload
docker rmi caddy:2-alpine traefik/whoami fortio/fortio >/dev/null 2>&1 || true
echo "cleaned: $(docker ps -a --filter name=cr- -q | wc -l) left"
