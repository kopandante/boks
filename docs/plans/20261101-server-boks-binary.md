# Plan: один boks на сервере — сборка CI и установка (boks#154, этап 1a)

Base: 544566c | Branch: feat/server-boks-binary

Решение владельца 01.11 («Сайт вообще не должен иметь понятия о boks»), задача infra-pm: этапы 1–3 #154.
Этот PR — этап 1a: серверный бинарь boks из CI, установка и проверка. Этап 1b (отдельный PR): `server
apply` и `proxy upgrade` собирают конфиг прокси серверным boks; `remote.Local` — там же или с этапом 3.

Не входит: выкат на прод-узлы, перевод сайтов — слово владельца.

## Validation Commands
- `go build ./... && go vet ./... && go test ./...` в корне
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags "-X main.commit=<sha>" ./cmd/boks` и `version`

## Acceptance Criteria
- AC1: CI на push в main собирает linux amd64/arm64 с `-X main.commit`, кладёт в release `bin-<commit>` с
  `SHA256SUMS`; существующий release не меняется.
- AC2: `server.yml` `boks: {commit, sha256}` — проверка формата (40 hex, 64 hex, amd64/arm64, sha256 обязателен).
- AC3: `InstallBoks`: архитектура сервера; сверка sha256 на машине оператора; запись 0700; сверка sha256 и
  `version` на сервере; атомарная смена ссылки; та же версия — не трогается; хранятся новая и предыдущая.
- AC4: отказы (другая сумма, другая версия, нет суммы для архитектуры) оставляют прежнюю ссылку и не
  оставляют отвергнутую сборку.
- AC5: `server install` и `server apply` ставят boks (apply — до политики; отказ — политика прежняя);
  `status` — версия и расхождение; `boks version`.
- AC6: мутации (проверка версии, уборка) роняют тесты.

## Pipeline
- [x] 0 worktree
- [x] 1 план (issue #154)
- [x] 2 реализация
- [x] 3 PR (#159)
- [ ] 4 review-loop green
- [ ] 5 merge
