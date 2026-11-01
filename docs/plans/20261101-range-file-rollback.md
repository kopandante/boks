# Plan: файл набора адресов не держит откат (после boks#140)

Base: 99d0bc8 | Branch: fix/range-file-rollback

Решение infra-pm 2026-11-01: (1) `rollback` берёт набор только из ревизии в истории и текущий
`ranges/jp.txt` не читает вовсе; (2) `apply` читает файл строго — пустой или пропавший: отказ с понятной
ошибкой; (3) `status` при битом файле показывает предупреждение, но не падает.
(4) boks#144, решение infra-pm: тем же PR — откат к ревизии до #142 вырезает адрес Worker'а
`2a06:98c0:3600::103` из `trusted_proxies` (`policyOfRevision`), как `apply`.

Не входит: скрипт APNIC (kopandante/backends, infra-dbauto), выкат, apply на hb-sites.

## Validation Commands
- `go build ./... && go vet ./... && go test ./...` в корне

## Acceptance Criteria
- AC1: `config.LoadServerForFleet` разбирает server.yml без чтения файлов наборов; остальное проверяется
  как при `LoadServer` (без `revision` — отказ).
- AC2: `boks server rollback` при удалённом jp.txt проходит и берёт ревизию из истории сервера.
- AC3: `boks server apply` с пропавшим файлом — `range_sets.jp: open`, с пустым — `range_sets.jp: empty`,
  до обращения к серверам.
- AC4: `boks server status` с пропавшим файлом — код 0 и строка `! … range_sets.jp … apply would refuse it`.
- AC6: `rollback` к ревизии с `2a06:98c0::/29` пишет 99 диапазонов вокруг адреса Worker'а и прочие
  диапазоны как были; адрес не доверен; проверка перед откатом читает ревизию так же.
- AC5: мутации — строгая загрузка у rollback, выключенное предупреждение status, проверка наборов при
  fleet-загрузке, выключенное вырезание при откате — роняют тесты.

## Pipeline
- [x] 0 worktree
- [x] 1 план
- [x] 2 реализация
- [x] 3 PR (#143)
- [ ] 4 review-loop green
- [ ] 5 merge
