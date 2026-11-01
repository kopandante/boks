# Plan: робот Яндекса — по обратному DNS, служебные фетчеры без поблажек (boks#162)

Base: 3277181 | Branch: feat/gate-yandex-dns

Зачем: `isYandex` пропускал мимо `fetch_meta`/`alpn`, `page_first`, `static_rhythm` и сигнатур любой UA с
`Yandex` из AS13238 — и робота поиска, и служебные фетчеры (Translate, превью, Metrika), которыми управляет
пользователь, как user-triggered у Google до #155. Русские сайты живут с поиска Яндекса: робота нельзя резать,
фетчерам поблажки не нужны. План — комментарий в #162.

Не входит: выкат образа gate15 на hb-sites (по слову владельца), сверка адреса/срока токена, модуль бана,
`bots.block`.

## Validation Commands
- `cd proxy/gate && go vet ./... && go test ./...` (и `-race`)
- `go build ./... && go vet ./... && go test ./...` в корне

## Acceptance Criteria
- AC1: робот поиска = UA с `YandexBot/`, `YandexMobileBot/`, `YandexImages/`, `YandexVideo/` или
  `YandexRenderResourcesBot/` + адрес AS13238 + PTR на `.yandex.ru|.net|.com` (точка в конце и регистр не
  мешают) + прямой резолв имени содержит адрес. Только он получает поблажки (`shadow`, `spared`).
- AC2: прочие `Yandex*` из AS13238 (YandexTranslate, YandexScreenshotBot) проверяются как браузер, сигнатура
  их режет; DNS у них не спрашивается.
- AC3: DNS — только для UA робота из AS13238; кэш по адресу: да 24 ч, нет 1 ч, сбой резолвера 1 ч (infra-pm,
  2026-11-02: не больше одного резолва на адрес в час); не больше 4096 адресов (сперва выкидываются истёкшие,
  потом любой); один запрос на адрес одновременно; один общий срок 400 мс на оба резолва, запрос не ждёт
  дольше, даже если резолвер срок не соблюдает; резолвер подставляется в тестах (`Handler.yandex`, `sharedYandex`), реальный DNS тесты не трогают.
- AC4: NXDOMAIN, чужое имя, прямой резолв не тот — не робот. Иная ошибка (таймаут, SERVFAIL, отказ) — вердикт
  прежний (AS13238 + UA робота) и `gate_yandex_dns: unavailable` в журнале запроса.
- AC5: образ `gate15` (`proxy/TAG`), `docs/architecture.md` описывает новое правило.

## Pipeline
- [x] 0 worktree
- [x] 1 план (комментарий #162)
- [x] 2 реализация: `proxy/gate/yandex.go`, вызовы в `checks.go` и `signature.go`
- [x] 3 тесты (`yandex_test.go`, правки `checks_test.go`, `signature_test.go`), мутации — все убиты
- [x] 4 TAG gate15, architecture.md
- [ ] 5 PR через /review-loop --ship, merge
