#!/usr/bin/env bash
# Generates nothing itself: /tmp/cs-a.json and /tmp/cs-b.json are configs printed by proxy.Config (a
# TLS host under a wildcard file and a plain host, dialling cs-a or cs-b), copied to the server first.
# Results on boks-lab 2026-10-06, caddy 2.11.7-alpine: the sysctl is 1 inside the container; busybox
# wget reaches the admin API only at 127.0.0.1 (localhost resolves to ::1); the TLS host on :80 gets a
# 308 to https; a forged X-Forwarded-For is replaced by the connection address; new certificate files
# are NOT picked up by a reload of an unchanged config, are by --force and by a changed config; a
# config naming a missing file is refused and the old one keeps serving; a 404 makes wget exit 1.
# Scratch facts for C1 on boks-lab: nothing named boks-*, loopback ports only.
set -uo pipefail
D=/tmp/csdir
cleanup() { docker rm -f cs-caddy cs-a cs-b >/dev/null 2>&1; docker network rm cs-net >/dev/null 2>&1; docker volume rm cs-certs >/dev/null 2>&1; rm -rf $D; }
cleanup
mkdir -p $D && cp /tmp/cs-a.json $D/caddy.json
docker network create cs-net >/dev/null
docker volume create cs-certs >/dev/null
docker run -d --name cs-a --network cs-net traefik/whoami --name A >/dev/null
docker run -d --name cs-b --network cs-net traefik/whoami --name B >/dev/null
mkcert() { docker run --rm -v cs-certs:/certs alpine sh -c "apk add -q openssl >/dev/null 2>&1; mkdir -p /certs/boks; openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=$1 -addext 'subjectAltName=DNS:*.example.test' -keyout /certs/boks/_.example.test.key -out /certs/boks/_.example.test.crt 2>/dev/null"; }
served() { echo | openssl s_client -connect 127.0.0.1:18443 -servername w.example.test 2>/dev/null | openssl x509 -noout -subject 2>/dev/null; }
mkcert gen1
docker create --name cs-caddy --sysctl net.ipv4.tcp_migrate_req=1 --network cs-net -p 127.0.0.1:18080:80 -p 127.0.0.1:18443:443 \
  -v cs-certs:/certs -v $D:/etc/boks:ro caddy:2.11.7-alpine caddy run --config /etc/boks/caddy.json >/dev/null
docker start cs-caddy >/dev/null; sleep 2
echo "1 sysctl in container: $(docker exec cs-caddy cat /proc/sys/net/ipv4/tcp_migrate_req)"
echo "1b admin answers: $(docker exec cs-caddy wget -q -O /dev/null http://localhost:2019/config/ && echo yes)"
echo "2 cert at start: $(served)"
echo "3 tls route: $(curl -sk --resolve w.example.test:18443:127.0.0.1 https://w.example.test:18443/ | grep -m1 Name)"
echo "3b plain route: $(curl -s -H 'Host: plain.example.test' http://127.0.0.1:18080/ | grep -m1 Name)"
echo "3c redirect of tls host on :80: $(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: w.example.test' http://127.0.0.1:18080/)"
echo "3d XFF passthrough: $(curl -sk --resolve w.example.test:18443:127.0.0.1 -H 'X-Forwarded-For: 6.6.6.6' https://w.example.test:18443/ | grep -i 'X-Forwarded-For')"
mkcert gen2
docker exec cs-caddy caddy reload --config /etc/boks/caddy.json >/dev/null 2>&1
echo "4 new files, unchanged reload: $(served)"
docker exec cs-caddy caddy reload --config /etc/boks/caddy.json --force >/dev/null 2>&1
echo "5 forced reload: $(served)"
mkcert gen3
cp /tmp/cs-b.json $D/caddy.next.json
docker exec cs-caddy caddy reload --config /etc/boks/caddy.next.json >/dev/null 2>&1
echo "6 changed-config reload: cert $(served), route $(curl -sk --resolve w.example.test:18443:127.0.0.1 https://w.example.test:18443/ | grep -m1 Name)"
echo "7 upstreams: $(docker exec cs-caddy wget -q -O - http://localhost:2019/reverse_proxy/upstreams)"
sed 's#_.example.test.crt#missing.crt#' /tmp/cs-a.json > $D/caddy.next.json
out=$(docker exec cs-caddy caddy reload --config /etc/boks/caddy.next.json 2>&1); echo "8 refused reload exit=$? route still $(curl -sk --resolve w.example.test:18443:127.0.0.1 https://w.example.test:18443/ | grep -m1 Name)"
echo "9 probe 404 exit: $(docker exec cs-caddy wget -q -O /dev/null -T 5 http://cs-a:80/nope; echo $?) / 200 exit: $(docker exec cs-caddy wget -q -O /dev/null -T 5 http://cs-a:80/; echo $?)"
cleanup
echo "cleaned: $(docker ps -a --filter name=cs- -q | wc -l) left; boks-proxy: $(docker ps --filter name=^boks-proxy$ --format '{{.Status}}')"
