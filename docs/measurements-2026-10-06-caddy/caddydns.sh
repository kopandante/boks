#!/usr/bin/env bash
# Switching without touching Caddy's config: the route dials a Docker DNS name (re-read every 1s),
# boks moves the name. Old copy leaves either by `network disconnect` or by `docker stop`.
# The real app image stands in for an app with graceful shutdown: nginx (SIGQUIT-less docker stop
# sends SIGTERM -> fast exit) vs whoami. Measured: errors under load over 10 switches.
set -euo pipefail
D=/tmp/caddydns
docker rm -f $(docker ps -aq --filter name=cd- ) >/dev/null 2>&1 || true
docker network rm cd-rt >/dev/null 2>&1 || true
docker network inspect cd-rt >/dev/null 2>&1 || docker network create cd-rt >/dev/null
cat > /tmp/caddydns.json <<'EOF'
{"admin":{"listen":"localhost:2019"},
 "apps":{"http":{"servers":{"boks":{"listen":[":80"],"routes":[
   {"match":[{"host":["h1.test"]}],"handle":[{"handler":"reverse_proxy",
     "dynamic_upstreams":{"source":"a","name":"app","port":"80","refresh":"1s"},
     "load_balancing":{"try_duration":"5s","try_interval":"100ms"}}],"terminal":true}
 ]}}}}}
EOF
docker run -d --name cd-caddy --network cd-rt -v /tmp/caddydns.json:/cfg/caddy.json:ro caddy:2-alpine caddy run --config /cfg/caddy.json >/dev/null
n=0
LAST=""
start() { n=$((n+1)); LAST=cd-app$n; docker run -d --name $LAST --network cd-rt --network-alias app traefik/whoami --name "v$n" >/dev/null; }
startquiet() { n=$((n+1)); LAST=cd-app$n; docker create --name $LAST traefik/whoami --name "v$n" >/dev/null; docker start $LAST >/dev/null; }
sleep 2
ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "cd-rt").IPAddress}}' cd-caddy)

run() { # $1 = how the old copy leaves: disconnect | stop ; $2 = keepalive flag
  docker rm -f $(docker ps -aq --filter name=cd-app) >/dev/null 2>&1 || true
  start; local cur=$LAST; sleep 2
  docker run --rm --network cd-rt --add-host h1.test:$ip fortio/fortio load -c 40 -qps 0 -t 30s $2 http://h1.test/ > /tmp/cd-$1$2.txt 2>&1 &
  local lp=$!
  sleep 3
  for i in $(seq 1 10); do
    # new copy starts OFF the route network (not reachable by the name), is "healthy", then joins with the alias
    startquiet; local new=$LAST
    docker network connect --alias app cd-rt "$new"
    sleep 1.5                       # > refresh: Caddy now knows both
    case $1 in
      disconnect) docker network disconnect cd-rt "$cur" ;;
      stop)       docker stop -t 5 "$cur" >/dev/null ;;
    esac
    sleep 1
    docker rm -f "$cur" >/dev/null
    cur=$new
  done
  wait $lp || true
  printf "%-10s %-18s %s\n" "$1" "${2:-keepalive}" "$(grep -E '^Code' /tmp/cd-$1$2.txt | tr '\n' ' ')"
}
run disconnect "-keepalive=false"
run stop "-keepalive=false"
run stop ""
echo "caddy restarts during the runs (should be 1, the boot): $(docker logs cd-caddy 2>&1 | grep -c 'server running')"

docker rm -f $(docker ps -aq --filter name=cd-) >/dev/null 2>&1 || true
docker network rm cd-rt >/dev/null
rm -f /tmp/caddydns.json /tmp/cd-*.txt
docker rmi caddy:2-alpine traefik/whoami fortio/fortio >/dev/null 2>&1 || true
echo "cleaned: $(docker ps -a --filter name=cd- -q | wc -l) left"
