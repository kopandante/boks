#!/usr/bin/env bash
# Hypothesis: reload errors are SO_REUSEPORT accept-queue resets when the old listener closes.
# If so, net.ipv4.tcp_migrate_req=1 (kernel migrates pending connections to the sibling listener)
# removes them. Pinned caddy:2.11.7-alpine; client = /tmp/hammer (Go, errors by kind), run from a
# container on the same network so the path is the same as for fortio before.
set -euo pipefail
IMG=caddy:2.11.7-alpine
docker rm -f $(docker ps -aq --filter name=cu-) >/dev/null 2>&1 || true
docker network inspect cu >/dev/null 2>&1 || docker network create cu >/dev/null
docker run -d --name cu-a --network cu traefik/whoami --name A >/dev/null
docker run -d --name cu-b --network cu traefik/whoami --name B >/dev/null
mkdir -p /tmp/cu
conf() { # $1 = handler JSON
  echo "{\"admin\":{\"listen\":\"localhost:2019\"},\"apps\":{\"http\":{\"servers\":{\"s\":{\"listen\":[\":80\"],\"routes\":[{\"handle\":[$1]}]}}}}}" > /tmp/cu/c.json
}
static() { conf "{\"handler\":\"static_response\",\"body\":\"v$1\"}"; }
proxy()  { conf "{\"handler\":\"reverse_proxy\",\"upstreams\":[{\"dial\":\"cu-$1:80\"}]}"; }

run() { # $1 label, $2 sysctl value, $3 static|proxy, $4 keepalive flag
  docker rm -f cu-caddy >/dev/null 2>&1 || true
  $3 a
  docker run -d --name cu-caddy --network cu --sysctl net.ipv4.tcp_migrate_req=$2 -v /tmp/cu:/cfg $IMG caddy run --config /cfg/c.json >/dev/null
  sleep 2
  docker run --rm --network cu -v /tmp/hammer:/hammer:ro alpine /hammer -url http://cu-caddy/ -c 40 -d 20s $4 > /tmp/cu/out.txt 2>&1 &
  local lp=$!
  sleep 3
  for i in $(seq 1 10); do
    if [ $((i % 2)) = 1 ]; then $3 b; else $3 a; fi
    docker exec cu-caddy caddy reload --config /cfg/c.json >/dev/null 2>&1 || echo "reload failed"
    sleep 1.3
  done
  wait $lp || true
  printf "%-34s %s\n" "$1" "$(cat /tmp/cu/out.txt)"
}
echo "kernel: $(uname -r)"
run "static, migrate_req=0"            0 static ""
run "static, migrate_req=1"            1 static ""
run "proxy,  migrate_req=0"            0 proxy  ""
run "proxy,  migrate_req=1"            1 proxy  ""
run "proxy,  migrate_req=1, keepalive" 1 proxy  "-ka"

docker rm -f $(docker ps -aq --filter name=cu-) >/dev/null 2>&1 || true
docker network rm cu >/dev/null
docker run --rm -v /tmp:/t alpine rm -rf /t/cu
echo "cleaned: $(docker ps -a --filter name=cu- -q | wc -l) left"
