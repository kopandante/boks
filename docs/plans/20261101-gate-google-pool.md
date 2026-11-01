# Plan: googlePool — только адреса обхода Googlebot (boks#138)

Base: a8c7bc2 (перенос на main после #137 и PR про общий CA) | Branch: fix/gate-google-pool-crawlers

Зачем: исключение гейта для пула Google (`googlePool`, boks#129) включало user-triggered-fetchers-google —
сервисы, которые программирует сам пользователь Google; скрейпер оттуда получал токен и проход с любого
адреса Google. Рендерер Googlebot ходит из common-crawlers (бывший googlebot.json). Решение cars-pm 01.11.

Образ: `proxy/TAG` → `ban10-gate10` (CI собирает образ; `DefaultProxyImage` и серверы не трогаются).

Не входит: request-gate в cars-cli (cars-gate), выкат образа (вместе с #137, по слову владельца),
`isGoogle` для `fetch_meta`/`alpn` (там user-triggered fetchers остаются — Read Aloud).

## Validation Commands
- `cd proxy/gate && go vet ./... && go test ./...`
- `go build ./... && go vet ./... && go test ./...` в корне

## Acceptance Criteria
- AC1: `googlePool` признаёт соседство только внутри `common-crawlers.json`.
- AC2: тест — токен Googlebot с соседнего адреса Googlebot (IPv4 и IPv6) → 200; токен Googlebot с адреса
  user-triggered (142.250.32.0/27 — только их), токен user-triggered с адреса Googlebot и с соседнего
  user-triggered → 403 ip_mismatch.
- AC3: `isGoogle` (fetch_meta, alpn) прежний: оба файла; `TestGoogleRanges` читает оба файла.
- AC4: мутация «googlePool через isGoogle» роняет тест.
- AC5: после выката образа — проверка по журналу: Googlebot на каталог сайтов hb-sites по-прежнему 200
  (по слову владельца, вне PR).

## Pipeline
- [x] 0 worktree
- [x] 1 план
- [x] 2 реализация
- [ ] 3 PR
- [ ] 4 review-loop green
- [ ] 5 merge
