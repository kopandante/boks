# Plan: X-Forwarded-For приложению = один адрес клиента (boks#136)

Base: a8c7bc2 | Branch: fix/xff-client-ip

Зачем: за `trusted_proxies` (Cloudflare) Caddy отдавал приложению цепочку XFF посетителя с реальным
адресом в конце; сайты берут первую запись (`getClientIp` в cars-cli lib/security) и верят подделке —
обход геоблока, банов, honeypot, лимитов, привязки токена к адресу (cars-backlog#110).

Не входит: выкат образа/apply на hb-sites, правки сайтов. Образ прокси не меняется (правка — конфиг).

## Validation Commands
- `go build ./... && go vet ./... && go test ./...` в корне
- `cd proxy/gate && go vet ./... && go test ./...` (живой Caddy: `TestForwardedForIsTheClientThroughCaddy`)
- `cd proxy/ban && go test ./...`

## Acceptance Criteria
- AC1: каждый маршрут приложения ставит `X-Forwarded-For: {http.vars.client_ip}` (header_up `set`) и
  по-прежнему удаляет `Forwarded`; с доверенными прокси и без.
- AC2: живой Caddy, доверенный 127.0.0.1: XFF «1.2.3.4, 198.51.100.7» (одной строкой и двумя
  заголовками) → приложение получает ровно `198.51.100.7`; IPv6-клиент — так же; без заголовка — адрес
  прокси; посетитель с ::1 с подделкой → `::1`.
- AC3: `X-Real-IP` boks не ставит (grep), пользовательские `X-Forwarded-*` в маршрутах уже запрещены
  (config.go) — `set` не с чем конфликтовать.
- AC4: для политики без `trusted_proxies_ca` формат маршрутов/маркера не поднят (todo#424), окно
  старых пинов описано в architecture.md; политика с CA требует формат 12 (`OriginPullFormat`, было
  11), чтобы boks без #137 (a8c7bc2) отказал громко, а не собрал конфиг без `set` (слово infra-pm,
  2026-11-01; AOP нигде не включён). Формат 11 по-прежнему читается, 13 — «новее этого boks».

## Pipeline
- [x] 0 worktree
- [x] 1 план
- [x] 2 реализация
- [ ] 3 PR
- [ ] 4 review-loop green
- [ ] 5 merge
