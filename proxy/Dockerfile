# The proxy boks runs on every server: Caddy with the forward proxy plugin, so the same container that
# serves the apps' hosts also carries the outgoing requests a service sends from this server's address
# (server.yml `egress:`). Stock Caddy has no forward proxy. Both versions are pinned: a proxy that
# changes under a moving tag changes every app's routing.
FROM caddy:2.11.7-builder-alpine AS build
RUN xcaddy build v2.11.7 --with github.com/caddyserver/forwardproxy@0aab84dad4fc2830789f34e27b4d7bc22a40889e

FROM caddy:2.11.7-alpine
COPY --from=build /usr/bin/caddy /usr/bin/caddy
RUN caddy list-modules | grep -qx http.handlers.forward_proxy
