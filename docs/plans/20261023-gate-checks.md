# Plan: проверки отпечатка в гейте — `checks` группы (режим тени)

Base: c596f16 | Branch: feat/gate-checks

Требование владельца: «блокировать не только по кукам, но и по фингерпринту». Замер 24 ч (21–22.10, Loki
hb-sites): 166 тыс. GET `/api/*` на хостах гейта, 69% — шторм dbauto (Mac Chrome/149, JP домашние адреса,
HTTP/1.1, токен через `POST /api/auth/token` с любым fp). Решения владельца 23.10 по развилкам: Google — мимо
`fetch_meta` и `alpn` по опубликованным диапазонам, не по UA; 86.57.245.110 (autogroup) — в исключения;
послабление 1.7.0 отменяется ради `fp`; токен только после страницы и JA4 — позже; отказы гейта в бан — пока
только журнал.

## Validation Commands
- `cd proxy/gate && go vet ./... && go test ./...`
- `go build ./... && go vet ./... && go test ./...` в корне
- `docker build proxy/` (проверка list-modules); образ собирает CI репо

## Acceptance Criteria
- AC1: `checks: {fp, fetch_meta, alpn: off|log|enforce, exempt_ranges}` в группе; `enforce` — только в группе
  `enforce`; диапазоны — адрес или CIDR, `/0` и IPv4 в записи IPv6 — отказ при загрузке конфига.
- AC2: проверки судят те же запросы, что токен: не exempt, не health, не Bearer.
- AC3: сработавшие проверки — `gate_shadow` в журнале доступа в любом режиме; в `log` ответ не меняется.
- AC4: `enforce`: проверка отказывает запросу, который токен пропустил: `fp` — 403 `Fingerprint mismatch`,
  остальные — 403 `Forbidden`; `gate_reason: check_<имя>`. Отказ самого токена остаётся прежним.
- AC5: `fp` — заголовок и fp в действительном токене; на путях `skip_fp` не спрашивается. `fetch_meta` —
  тройка, на `skip_fp` — только `Sec-Fetch-Site: same-origin`. `alpn` — UA браузера, прямой TLS, не h2;
  за доверенным прокси не спрашивается.
- AC6: адреса Googlebot (common-crawlers.json) и user-triggered fetchers Google — проходят `fetch_meta` и
  `alpn`, но не `fp`; `exempt_ranges` — все проверки.
- AC7: поле обработчика: boks не меняется, формат не меняется; образ `…-ban9-gate3-…`.

## Pipeline
- [x] 0 worktree
- [x] 1 план (scratchpad plan-gate-fp.md, решения владельца 23.10)
- [x] 2 реализация
- [ ] 3 PR
- [ ] 4 review-loop green (agent-only, codex в лимите)
- [ ] 5 merge, образ gate3, DefaultProxyImage по digest
- [ ] 6 выкатка образа на hb-sites
- [ ] 7 пин boks по флоту hb-sites, политика hb-sites: `checks` в log на всех группах
- [ ] 8 enforce по группам — по метрикам (раздел ниже)

## Enforce
- dbauto `alpn` — после 3 суток log; затем `fetch_meta` и `fp` на группах шаблона по одной-две в день,
  начиная с групп без трафика; `alpn` на остальных; encarexport `fp` — после клиента cars-cli в сайте и
  сужения `skip_fp` до картинок.
- Переход по группе и проверке: у похожих на людей (fp + тройка + h2, не шторм) `gate_shadow` меньше 0,5%
  запросов группы и не больше 3 адресов в сутки, 3 суток подряд, каждый адрес разобран; у известных сборщиков
  доля в тени больше 95%.

## Non-goals
- JA4 и разбор ClientHello; токен только после страницы; бан по отказам гейта.
