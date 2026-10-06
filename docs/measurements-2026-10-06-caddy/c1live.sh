#!/usr/bin/env bash
# C1 live step, 2026-10-06: a real `boks deploy`, rollback and failed deploy under load after
# `boks proxy migrate`, on a fresh server (OrbStack machine boks-lab2: Ubuntu noble arm64, kernel 7.0,
# Docker 29.1) — boks-lab itself was busy with the live checks of other PRs, which need kamal-proxy.
# boks-main is origin/main (kamal-proxy), boks-tip the Caddy branch; hammer is the Go client of
# caddyreuse.sh with a -host flag, copied to the server. Run from a directory holding boks.yml:
#   app: web / image: traefik/whoami / servers: [root@boks-lab2@orb] / deploy_timeout: 20s
#   ports: [{name: web, port: 80, host: web.lab2.test}]
# Results (keep-alive unless said):
#   migrate (kamal-proxy → Caddy)  short outage on the swap — expected: a proxy change restarts 80/443
#   deploy v1.10.3                 289044 ok, 0 errors
#   deploy v1.11.0, no keep-alive  253778 ok, 12 EOF (the residual per reload, as measured before)
#   rollback                       398059 ok, 0 errors
#   failed deploy (health fails)   451208 ok, 0 errors; the new copy removed, the old one serving
set -u
S=root@boks-lab2@orb
load() { ssh $S "hammer -url http://127.0.0.1/ -host web.lab2.test -c 40 -d $1 $2"; }
./boks-main deploy v1.10.2
(load 25s -ka > migrate.txt) & sleep 3; ./boks-tip proxy migrate; wait; cat migrate.txt
(load 40s -ka > l1.txt) & sleep 3; ./boks-tip deploy v1.10.3; wait; cat l1.txt
(load 40s "" > l2.txt) & sleep 3; ./boks-tip deploy v1.11.0; wait; cat l2.txt
(load 40s -ka > l3.txt) & sleep 3; ./boks-tip rollback; wait; cat l3.txt
sed 's/^deploy_timeout: 20s/deploy_timeout: 15s\ncommand: ["--port", "9999"]/' boks.yml > boks-bad.yml
(load 45s -ka > l4.txt) & sleep 3; ./boks-tip -f boks-bad.yml deploy v1.10.2; wait; cat l4.txt
