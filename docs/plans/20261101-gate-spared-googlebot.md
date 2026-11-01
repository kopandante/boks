# Plan: spared — только Googlebot, без user-triggered fetchers (boks#151)

Base: 8f0c85a | Branch: fix/gate-spared-googlebot

Решение infra-pm 01.11, логика как в #138: `spared` (page_first, static_rhythm, сверка и бан сигнатур)
сужается до `isGooglebot`. User-triggered fetchers Google (Apps Script и т. п. — их программирует
пользователь) остаются исключением только в `fetch_meta` и `alpn` (Read Aloud и подобное).

Образ: `proxy/TAG` → `ban10-gate12` (CI собирает образ). Не входит: выкат образа на hb-sites — слово владельца.

## Validation Commands
- `cd proxy/gate && go vet ./... && go test ./...`
- `go build ./... && go vet ./... && go test ./...` в корне

## Acceptance Criteria
- AC1: скрейпер из 142.250.32.x с токеном на свой адрес — совпадение сигнатуры, 403 и бан; page_first без
  страницы и static_rhythm после серийных файлов — 403.
- AC2: Googlebot (66.249.66.1) — по-прежнему мимо всех трёх.
- AC3: `fetch_meta`/`alpn` для user-triggered fetchers — по-прежнему исключение (Read Aloud, TestShadowByClient).
- AC4: `docs/architecture.md`: исключение — Googlebot, не «Google целиком».
- AC5: мутация `spared` через `isGoogle` роняет тесты.

## Pipeline
- [x] 0 worktree
- [x] 1 план
- [x] 2 реализация
- [x] 3 PR (#155)
- [x] 4 review-loop green
- [ ] 5 merge
