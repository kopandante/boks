# Plan: повтор pull — ещё три слова (boks#153, продолжение)

Base: 544566c | Branch: fix/pull-retry-ssh

Решение infra-pm 01.11: в повтор `broken pipe`, `temporary failure in name resolution` (временный сбой DNS,
в отличие от `no such host`), `closed by remote host`. docker pull идемпотентен — повтор после оборванного
ssh безопасен.

## Validation Commands
- `go build ./... && go vet ./... && go test ./...` в корне

## Acceptance Criteria
- AC1: `registryDown` — true для трёх слов в формулировках docker и ssh.
- AC2: `no such host` по-прежнему отказ.
- AC3: мутация — без трёх слов — роняет тест.

## Pipeline
- [x] 0 worktree
- [x] 1 план
- [x] 2 реализация
- [ ] 3 PR
- [ ] 4 review-loop green
- [ ] 5 merge
