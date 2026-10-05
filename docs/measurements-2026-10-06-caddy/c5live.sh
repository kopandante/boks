#!/usr/bin/env bash
# C5 + :80 ownership, checked with the config boks's own Config() assembled, on caddy:2.11.7-alpine.
# /tmp/c5.json is what boks's proxy.Config() assembles for this policy and these routes (a throwaway
# test wrote it): allow img.dev.habsidev.com /pics,/pics_i for (?i)telegrambot; block "infra"
# domains [habsidev.com] (?i)(bot|crawler|spider); block "crawlers" (?i)(bingbot|gptbot); routes
# shop.example.test (TLS, cert file) and plain.example.test (HTTP) → cf5-up, img.dev.habsidev.com
# (TLS, cert file) → cf5-gw, x.habsidev.com (HTTP) → cf5-up. Result on boks-lab 2026-10-06: 16/16 as
# expected, no ACME attempt in Caddy's log.
set -uo pipefail
IMG=caddy:2.11.7-alpine
docker rm -f $(docker ps -aq --filter name=cf5-) >/dev/null 2>&1 || true
docker network inspect cf5 >/dev/null 2>&1 || docker network create cf5 >/dev/null
docker run -d --name cf5-up --network cf5 traefik/whoami --name UP >/dev/null
docker run -d --name cf5-gw --network cf5 traefik/whoami --name GW >/dev/null
mkdir -p /tmp/cf5/etc /tmp/cf5/certs/boks
cp /tmp/c5.json /tmp/cf5/etc/caddy.json
docker run --rm -v /tmp/cf5/certs/boks:/o alpine/openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj /CN=t \
  -addext "subjectAltName=DNS:shop.example.test,DNS:img.dev.habsidev.com" -keyout /o/t.key -out /o/t.crt >/dev/null 2>&1
docker run -d --name cf5-caddy --network cf5 -v /tmp/cf5/etc:/etc/boks:ro -v /tmp/cf5/certs:/certs $IMG caddy run --config /etc/boks/caddy.json >/dev/null
sleep 3
ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "cf5").IPAddress}}' cf5-caddy)
c() { docker run --rm --network cf5 curlimages/curl -sk -o /dev/null -w '%{http_code} %{redirect_url}' --resolve "$1:80:$ip" --resolve "$1:443:$ip" -A "$2" "$3"; }
chk() { got=$(c "$2" "$3" "$4"); case "$got" in $5*) r=ok;; *) r=FAIL;; esac; printf '%-4s %-62s want %-4s got %s\n' "$r" "$1" "$5" "$got"; }
chk "https shop, browser"                     shop.example.test "Mozilla/5.0" https://shop.example.test/ 200
chk "https shop, GPTBot (crawlers, any host)" shop.example.test "GPTBot/1.0" https://shop.example.test/ 403
chk "https shop, SomeBot (infra not here)"    shop.example.test "SomeBot/2" https://shop.example.test/ 200
chk "http x.habsidev.com, SomeBot (infra)"    x.habsidev.com "SomeBot/2" http://x.habsidev.com/ 403
chk "http x.habsidev.com, browser"            x.habsidev.com "Mozilla/5.0" http://x.habsidev.com/ 200
chk "http x.habsidev.com ACME path, SomeBot"  x.habsidev.com "SomeBot/2" http://x.habsidev.com/.well-known/acme-challenge/abc 200
chk "https img /pics/1.jpg, TelegramBot"      img.dev.habsidev.com "TelegramBot (like TwitterBot)" https://img.dev.habsidev.com/pics/1.jpg 200
chk "https img /pics_i, TelegramBot"          img.dev.habsidev.com "TelegramBot (like TwitterBot)" https://img.dev.habsidev.com/pics_i 200
chk "https img /other, TelegramBot"           img.dev.habsidev.com "TelegramBot (like TwitterBot)" https://img.dev.habsidev.com/other 403
chk "https img /picsX, TelegramBot (boundary)" img.dev.habsidev.com "TelegramBot (like TwitterBot)" https://img.dev.habsidev.com/picsX 403
chk "https img /pics, other bot"              img.dev.habsidev.com "SomeBot/2" https://img.dev.habsidev.com/pics/1 403
chk "http shop, browser -> redirect"          shop.example.test "Mozilla/5.0" http://shop.example.test/a?b=1 "308 https://shop.example.test/a?b=1"
chk "http plain, browser"                     plain.example.test "Mozilla/5.0" http://plain.example.test/ 200
chk "http unknown, browser -> 404"            unknown.test "Mozilla/5.0" http://unknown.test/ 404
chk "http unknown, GPTBot -> 403"             unknown.test "GPTBot/1.0" http://unknown.test/ 403
echo "--- Host with case and port (header):"
docker run --rm --network cf5 curlimages/curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: X.HabsiDev.com:80' -A SomeBot http://$ip/
echo "--- ACME/obtain lines in Caddy's log:"
docker logs cf5-caddy 2>&1 | grep -iE 'obtain|acme|certificate' | grep -v 'skipping automatic certificate management' | head -5
echo "(end)"
docker rm -f $(docker ps -aq --filter name=cf5-) >/dev/null 2>&1
docker network rm cf5 >/dev/null
docker run --rm -v /tmp:/t alpine rm -rf /t/cf5 /t/c5.json
docker rmi traefik/whoami curlimages/curl alpine/openssl >/dev/null 2>&1 || true
echo "cleaned: $(docker ps -a --filter name=cf5- -q | wc -l) left"
