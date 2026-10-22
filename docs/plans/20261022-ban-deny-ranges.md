# Plan: `ban.deny_ranges` — статический список адресов, которым прокси отказывает

Base: 8260f05 | Branch: feat/ban-deny-ranges

Решение владельца (22.10): защита живёт в прокси, а не в nftables. Первый адрес — 89.167.100.21
(сборщик отчётов encarexport, UA n8n); сейчас его режет временная nft-цепочка `inet filter blockpre`
на hb-sites.

## Validation Commands
- `go build ./... && go vet ./... && go test ./...` в корне
- `cd proxy/ban && go vet ./... && go test ./...`
- `docker build proxy/` (в Dockerfile — проверка list-modules); образ собирает CI репо

## Acceptance Criteria
- AC1: `ban.deny_ranges` в server.yml проверяется как `exempt_ranges`: адрес или CIDR, /0 запрещён,
  IPv4 в записи IPv6 запрещён; в политике — маскированные CIDR.
- AC2: запрос с `client_ip` из `deny_ranges` получает 403 до эвристик, счётчиков и исключений;
  адрес тот же, что у бана (за `trusted_proxies` — настоящий клиент, без переменной — соединение).
- AC3: deny главнее `exempt_ranges`, частных сетей и `bots.allow`: маршрут бана получает второй набор
  матчеров `client_ip` по `deny_ranges`, мимо `not` с allows.
- AC4: журнал — одна строка warn `address denied` на адрес за `duration`; память строк ограничена
  `max_tracked`.
- AC5: маршрут бана стоит первым, до блоков и гейта, — тест на собранном конфиге с гейтом.
- AC6: политика без `deny_ranges` собирается в те же байты, что раньше; маркер — 7/8, как раньше.
  С `deny_ranges` маркер — формат 9 (boks формата 8 иначе собрал бы конфиг без deny и молча снял бы
  его); `CheckBan` пробует `deny_ranges` в образе только когда они есть в политике.
- AC7: старый boks (пин e57f5b7, формат 8) на узле с deny отказывает громко и ничего не меняет;
  откат на ревизию без deny открывает узел ему сразу.

## Pipeline
- [x] 0 worktree
- [x] 1 план
- [x] 2 реализация
- [x] 3 PR (#116)
- [x] 4 review-loop green (agent-only, codex в лимите)
- [ ] 5 merge, образ, DefaultProxyImage по digest
- [ ] 6 выкатка образа: hb-sites, hb-shchr, hb-poolapi
- [ ] 7 пин boks по флоту (формат 9), PR политики hb-sites, apply
- [ ] 8 проверка в журнале, удаление `inet filter blockpre`

### Task 1: config
- [x] `Ban.DenyRanges`, `DenyPrefixes`, проверки + тесты; `policyOf`.

### Task 2: policy/caddy
- [x] `Ban.DenyRanges`, handler, матчер `client_ip` в `banRoute`, `String`, `DenyFormat = 9`,
  `policyFormat`, чтение маркера до 9, `CheckBan` с deny в пробе + тесты.

### Task 3: proxy/ban
- [x] `deny_ranges`: 403 первым делом, журнал раз в `duration`, ограничение памяти + тесты.

### Task 4: docs, образ
- [x] `docs/architecture.md` — раздел бана; proxy/TAG `…-ban9-…`; DefaultProxyImage по digest после сборки CI.

## Non-goals
- nftables, ipset; динамический список (API, файл на узле).
