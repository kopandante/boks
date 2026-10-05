#!/usr/bin/env bash
# Does Caddy's /reverse_proxy/upstreams show the old copy's requests in flight after a reload? The
# deploy's drain waits on exactly this. A 6s request goes to cs-a, the config is reloaded to cs-b, and
# the upstreams are read every second. Measured on boks-lab 2026-10-06 (caddy 2.11.7-alpine): cs-a
# stays listed with num_requests 1 until the slow request is answered (by A), then drops out; a new
# request goes to B. Loopback port only, nothing named boks-*.
set -u
D=/tmp/csdrain
docker rm -f cs-caddy cs-a cs-b >/dev/null 2>&1; docker network rm cs-net >/dev/null 2>&1; rm -rf $D; mkdir -p $D
cfg() { echo "{\"admin\":{\"listen\":\"localhost:2019\",\"config\":{\"persist\":false}},\"apps\":{\"http\":{\"servers\":{\"http\":{\"listen\":[\":80\"],\"routes\":[{\"match\":[{\"host\":[\"p.test\"]}],\"handle\":[{\"handler\":\"reverse_proxy\",\"upstreams\":[{\"dial\":\"$1:80\"}]}],\"terminal\":true}]}}}}}"; }
cfg cs-a > $D/caddy.json; cfg cs-b > $D/caddy.next.json
docker network create cs-net >/dev/null
docker run -d --name cs-a --network cs-net traefik/whoami --name A >/dev/null
docker run -d --name cs-b --network cs-net traefik/whoami --name B >/dev/null
docker run -d --name cs-caddy --sysctl net.ipv4.tcp_migrate_req=1 --network cs-net -p 127.0.0.1:18080:80 -v $D:/etc/boks:ro caddy:2.11.7-alpine caddy run --config /etc/boks/caddy.json >/dev/null; sleep 2
up() { docker exec cs-caddy wget -q -O - http://127.0.0.1:2019/reverse_proxy/upstreams; }
(curl -s -H "Host: p.test" "http://127.0.0.1:18080/?wait=6s" | grep -m1 Name > $D/slow.txt) &
sleep 1; echo "before reload: $(up)"
docker exec cs-caddy caddy reload --config /etc/boks/caddy.next.json 2>/dev/null; echo "reload exit $?"
for i in 1 2 3 4 5 6 7; do echo "t+$i: $(up)"; sleep 1; done
wait; echo "slow request answered by: $(cat $D/slow.txt)"
echo "new request: $(curl -s -H "Host: p.test" http://127.0.0.1:18080/ | grep -m1 Name)"
docker rm -f cs-caddy cs-a cs-b >/dev/null; docker network rm cs-net >/dev/null; rm -rf $D
