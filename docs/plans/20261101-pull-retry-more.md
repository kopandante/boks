# Plan: шире список сетевых ошибок повтора pull (boks#153)

Base: 8f0c85a | Branch: fix/pull-retry-more

Решение infra-pm 01.11: расширить сразу, не ждать новых сбоев. В повтор: connection timed out, connection
refused, no route to host, network is unreachable, server misbehaving, голый EOF, HTTP 502/503/504,
context deadline exceeded. Сразу отказ: no such host, авторизация, manifest unknown. Pull образа прокси —
без повтора.

## Validation Commands
- `go build ./... && go vet ./... && go test ./...` в корне

## Acceptance Criteria
- AC1: `registryDown` — true для каждого слова из списка, в формулировках docker.
- AC2: false для `no such host` (и вместе с сетевыми словами), отказа токена, `manifest unknown`.
- AC3: `EOF` — только отдельным словом (не внутри digest или слова); 502/503/504 — только с текстом статуса HTTP
  (`502 Bad Gateway`): тег образа `503` или порт реестра в тексте ошибки и в URL манифеста — не сеть (ревью #156).
- AC4: мутации — без отдельных слов, голое число 50x, без отказа `no such host` — роняют тест.

## Pipeline
- [x] 0 worktree
- [x] 1 план
- [x] 2 реализация
- [x] 3 PR
- [ ] 4 review-loop green
- [ ] 5 merge
