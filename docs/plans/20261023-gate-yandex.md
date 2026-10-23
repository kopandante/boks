# Plan: роботы Яндекса мимо `fetch_meta` и `alpn` гейта

Base: 0dfd71c | Branch: feat/gate-yandex

Решение владельца 23.10 («Пропускать»): YandexBot, YandexRenderResourcesBot и прочие Yandex* проходят
`fetch_meta` и `alpn` по проверенным адресам Яндекса — как Googlebot и Read Aloud по диапазонам Google. В журнале
`gate_shadow` ревизии 34 (log): dkauto, 213.180.203.222 и .232 — YandexRenderResourcesBot, HTTP/1.1 без Sec-Fetch,
`fetch_meta,alpn`. Все адреса роботов Яндекса из журнала (dkauto, pakim) — `*.spider.yandex.com` в обе стороны.

## Решение: статический список AS13238, не rDNS в прокси
- Яндекс не публикует JSON диапазонов; его способ — PTR на yandex.ru/.net/.com и прямой DNS обратно.
- rDNS на запросе: ожидание резолвера на каждом запросе, не прошедшем проверку, кэш со своими границами,
  упавший резолвер решает вердикт. Статический список: без сети на запросе, тестируется, как у Google.
- Список — анонсы AS13238 (Yandex LLC) из RIPEstat на 23.10, в образе (`proxy/gate/yandex/as13238.txt`).
  Yandex Cloud — AS200350, пересечений нет (сверено). Пропуск — только UA с `Yandex` и адрес из списка;
  UA Яндекса с чужого адреса и браузер с адреса Яндекса проверяются как обычно; `fp` не снимается.

## Validation Commands
- `cd proxy/gate && go vet ./... && go test ./...`
- `go build ./... && go vet ./... && go test ./...` в корне

## Acceptance Criteria
- AC1: UA с `Yandex` с адреса из AS13238 проходит `fetch_meta` и `alpn`, не `fp`.
- AC2: UA Яндекса с чужого адреса (в т.ч. Yandex Cloud) и не-Яндекс UA с адреса Яндекса — как обычно.
- AC3: файл списка читается целиком тестом; строка не префикс или `/0` — ошибка.
- AC4: образ `…-ban9-gate4-…`; формат узла и boks не меняются.

## Pipeline
- [x] 0 worktree
- [x] 1 план
- [x] 2 реализация
- [x] 3 PR (#122)
- [x] 4 review-loop green (agent-only, codex в лимите: 2 раунда по 2 линзы, 0 находок)
- [x] 5 merge (#122 6a235fb), образ gate4, DefaultProxyImage по digest
- [ ] 6 выкатка образа на hb-sites, политика hb-sites (комментарий), пин boks по флоту
- [ ] 7 проверка по журналу `gate_shadow`: роботы Яндекса с адресов Яндекса без `fetch_meta`/`alpn`
