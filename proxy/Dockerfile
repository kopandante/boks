# The proxy boks runs on every server: Caddy with the forward proxy plugin, so the same container that
# serves the apps' hosts also carries the outgoing requests a service sends from this server's address
# (server.yml `egress:`), with boks's own ban handler (ban/, server.yml `ban:`), which refuses an
# address that sends too many requests, and its gate (gate/, server.yml `gate:`), which checks the sites'
# API token in place of each site. Stock Caddy has none of them. Both versions are pinned: a proxy that
# changes under a moving tag changes every app's routing. boks's handlers are built from this directory,
# the build's context, so the image carries the code of the commit it was built from.
FROM caddy:2.11.7-builder-alpine AS build
COPY ban /src/ban
COPY gate /src/gate
RUN xcaddy build v2.11.7 --with github.com/caddyserver/forwardproxy@0aab84dad4fc2830789f34e27b4d7bc22a40889e \
	--with github.com/kopandante/boks/proxy/ban=/src/ban \
	--with github.com/kopandante/boks/proxy/gate=/src/gate

FROM caddy:2.11.7-alpine
COPY --from=build /usr/bin/caddy /usr/bin/caddy
RUN caddy list-modules | grep -qx http.handlers.forward_proxy && caddy list-modules | grep -qx http.handlers.boks_ban \
	&& caddy list-modules | grep -qx http.handlers.boks_gate
