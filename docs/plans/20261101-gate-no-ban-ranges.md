# Plan: checks.no_ban_ranges — отказ по сигнатуре без бана (boks#160)

Base: 879488d | Branch: feat/gate-no-ban-ranges

Решение владельца 01.11 «блокируем, но не баним» (для офисов клиентов — «Да»), задача infra-pm; ревизия 64
у infra-dbauto ждёт эту правку. Образ: `proxy/TAG` → `ban10-gate14` (gate13 — у #131). Выкат — слово владельца.

## Validation Commands
- `cd proxy/gate && go vet ./... && go test ./...`
- `go build ./... && go vet ./... && go test ./...` в корне

## Acceptance Criteria
- AC1: адрес из `no_ban_ranges` + enforce-сигнатура → 403, `gate_reason: signature`, `gate_signature`; бана нет.
- AC2: адрес из списка + обычный браузер без h2 и Fetch Metadata, без страницы до API, после серийных файлов → 200.
- AC3: `exempt_ranges` — как раньше (мимо сигнатур, без записи); прочий адрес — 403 и бан.
- AC4: пересечение `exempt_ranges` и `no_ban_ranges`, `/0` — отказ.
- AC5: строгий декодер принимает поле.
- AC6: мутации (бан при совпадении, проверки, page_first) роняют тест.

## Pipeline
- [x] 0 worktree
- [x] 1 план (issue #160)
- [x] 2 реализация
- [x] 3 PR (#161)
- [ ] 4 review-loop green
- [ ] 5 merge
