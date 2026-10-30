# Plan: сигнатуры заголовков в гейте (`signatures`, `signature_ban`)

Base: afbf32b | Branch: feat/gate-signatures | Задача: kopandante/todo#419

Слово владельца (30.10, через infra-pm): полностью закрыть скрейперу cars.dbauto.kr сбор данных —
эвристики и правила по отпечаткам на входном прокси hb-sites, баны адресов, с которых он выходит.

## Замер (журнал boks-proxy hb-sites в Loki, 29.10–30.10)

- Бот: ~92 тыс. запросов за сутки к cars.dbauto.kr с 1 393 японских бытовых адресов, h2, токен, отпечаток,
  все Sec-Fetch-*, Mac Chrome/149 — гейт и `alpn` его пропускают.
- `Accept-Encoding: br, gzip, deflate` под браузерным UA: 82,8 тыс. совпадений за сутки, 355 тыс. за трое,
  все — один из трёх UA бота; **ни одного** запроса страницы, `/_next/` или картинки с совпавших адресов.
  Chrome шлёт `gzip, deflate, br, zstd`, Safari — `gzip, deflate, br`. На хостах Convex и бэкендов тот же
  заголовок шлёт серверный Node fetch (UA `node`) — поэтому правило в группе dbauto и с шаблоном на UA.
- Бот никогда не шлёт `Priority`; адреса меняются быстрее, чем их можно вписать в `deny_ranges`
  (из 37 адресов последнего часа раньше встречались 7) — нужен бан по признаку, а не список.

## Решение

Поле обработчика `boks_gate` (boks его не читает — новый образ и ревизия политики, не новый boks и не
пин флота): `signatures: [{name, mode, headers: [{name, pattern}]}]`, `signature_ban`. Сигнатура
спрашивается у любого запроса хостов группы до токена; enforce — 403 и бан адреса на `signature_ban`
во всей группе (страницы тоже). Баны — в памяти пакета, переживают reload. Google/Яндекс и
`checks.exempt_ranges` — мимо.

## Validation Commands
- `go build ./... && go vet ./... && go test ./...` в корне
- `cd proxy/gate && go vet ./... && go test ./...`
- `docker build proxy/` — собирает CI репо

## Acceptance Criteria
- AC1: сигнатура совпадает, когда каждый заголовок подходит под свой RE2 (отсутствующий = `""`);
  сигнатура, все шаблоны которой принимают `""`, отказана при проверке.
- AC2: enforce — 403 `Forbidden`, `gate_reason: signature`; с `signature_ban` — 403 `signature_ban` на
  любой запрос группы с адреса (API, страница, выдача токена) до конца срока; другой группе бан не виден.
- AC3: log — только `gate_signature` в журнале, ответ не меняется, адрес не банится.
- AC4: Google, роботы Яндекса и `checks.exempt_ranges` не сопоставляются.
- AC5: бан переживает reload (новый обработчик группы); хранилище ограничено (200 тыс.), полное — отказ без бана.
- AC6: `server.yml` с сигнатурами разбирается boks без изменений кода CLI (заголовки — значения, не ключи).

## Pipeline
- [x] 0 worktree
- [x] 1 план
- [x] 2 реализация (proxy/gate/signature.go + тесты, мутации 5/5 убиты)
- [x] 3 PR (#127)
- [ ] 4 review-loop green
- [ ] 5 merge, образ gate5, DefaultProxyImage по digest
- [ ] 6 `boks proxy upgrade` на hb-sites (слово infra-pm — перезапуск прокси)
- [ ] 7 backends: ревизия 39 — сигнатура в log, замер; ревизия 40 — enforce + `signature_ban: 24h`

## Non-goals
- Бан во всех группах/хостах узла (модуль `boks_ban`) — потребовал бы новый формат и пин флота.
- JA3/JA4: Caddy не отдаёт ClientHello обработчику без своего listener-модуля.
