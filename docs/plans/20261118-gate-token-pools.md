# Plan: пул токена в гейте — адреса одного набора делят токен (todo#419, пул Meta)

Base: 73bd33e | Branch: feat/gate-token-pools

Зачем: посетитель из встроенного браузера Facebook получает токен страницы на одном адресе пула Meta
(57.141.20.34), а API зовёт с другого (57.141.20.42) → `ip_mismatch` → карточка без данных. Слово владельца
18.11 «Чинить защиту» (ответ дашборда 75008eb6-2510-4955-8c38-1355b14478c4), вариант (1) комментария 16.11 в
todo#419: пул по образцу `googlePool`, наборы — по анонсам AS32934 (`range_sets`).

## Validation Commands
- `cd proxy/gate && go vet ./... && go test ./... -count=1`
- `go test ./internal/... -count=1`
- `cd proxy/gate && go test . -run TokenPool -count=1 -v`

## Acceptance Criteria
- AC1: токен, выданный 57.141.20.34, принимается с 57.141.20.42 в группе с `token_pools: [meta]`.
- AC2: адрес вне набора, адрес другого набора, посетитель с обычным адресом — `ip_mismatch`; IPv6 и IPv4-mapped работают.
- AC3: без `token_pools` привязка к адресу прежняя.
- AC4: `token_pools` с неизвестным/пустым набором — отказ при Provision и при `apply` (`withRangeSets`).
- AC5: набор, названный только в `token_pools`, пишется в JSON группы; группа без `token_pools` не меняется.
- AC6: мутации (убрать условие; `&&`→`||` в samePool) валят `TestTokenPool`.

## Pipeline
- [x] 1 поле `TokenPools`, `samePool`, Provision, `withRangeSets`
- [x] 2 тесты proxy/gate и internal/config, мутации
- [x] 3 docs/architecture.md
- [ ] 4 PR через /review-loop, certify, merge
- [ ] 5 следующий PR: `proxy/TAG` → gate17 (образ прокси)
