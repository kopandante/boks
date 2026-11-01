# Plan: просроченный токен Googlebot проходит с адреса Googlebot до суток (todo#419, PR #131)

Base: main | Branch: fix/gate-google-expired

Рендерер Googlebot зовёт API с токеном, сохранённым с прошлого обхода, и на 401 нового не просит
(cars.dbauto.kr 30.10, 66.249.77.192: все запросы к `/api/auctions/autohub/…` — 401 `expired`).
`decideToken` снимает отказ `expired`, если токен выдан не больше `googleGrace` (24 ч) назад, не «из
будущего», и адрес токена и адрес запроса — адреса обхода Googlebot (`googlePool` → `isGooglebot`,
только `common-crawlers.json` после #138/#149; user-triggered fetchers Google — нет).

Образ: `proxy/TAG` → `ban10-gate13` (gate12 занимает #155; влить после него). Не входит: выкат образа,
`DefaultProxyImage`, проверка срока на сайтах с `site_gate: on` (kopandante/cars-backlog#110).

## Validation Commands
- `cd proxy/gate && go vet ./... && go test ./...`
- `go build ./... && go vet ./... && go test ./...` в корне

## Acceptance Criteria
- AC1: просроченный токен Googlebot с адреса Googlebot в пределах 24 ч с выдачи — 200 (`TestGoogleLate`).
- AC2: после 24 ч, токен «из будущего», токен или адрес посетителя, user-triggered fetcher 142.250.32.5 — 401.
- AC3: `docs/architecture.md`, «Проверка»: оба исключения Googlebot и что fetchers в них не входят.
- AC4: мутации `age >= 0`, предела 24 ч и `googlePool` роняют `TestGoogleLate`.

## Pipeline
- [x] 0 worktree
- [x] 1 план
- [x] 2 реализация
- [x] 3 PR (#131)
- [x] 4 review-loop green
- [ ] 5 merge (после #155)
