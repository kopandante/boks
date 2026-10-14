# The proxy boks runs on every server: Caddy with the forward proxy plugin, so the same container that
# serves the apps' hosts also carries the outgoing requests a service sends from this server's address
# (server.yml `egress:`), and with boks's own ban handler (ban/, server.yml `ban:`), which refuses an
# address that sends too many requests. Stock Caddy has neither. Both versions are pinned: a proxy that
# changes under a moving tag changes every app's routing. The ban handler is built from this directory,
# the build's context, so the image carries the code of the commit it was built from.
FROM caddy:2.11.7-builder-alpine AS build
COPY ban /src/ban
RUN xcaddy build v2.11.7 --with github.com/caddyserver/forwardproxy@0aab84dad4fc2830789f34e27b4d7bc22a40889e \
	--with github.com/kopandante/boks/proxy/ban=/src/ban

FROM caddy:2.11.7-alpine
COPY --from=build /usr/bin/caddy /usr/bin/caddy
RUN caddy list-modules | grep -qx http.handlers.forward_proxy && caddy list-modules | grep -qx http.handlers.boks_ban
