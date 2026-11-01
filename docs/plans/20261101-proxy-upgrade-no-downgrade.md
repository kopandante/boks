# Plan: proxy upgrade не ставит образ старше работающего (boks#145)

Base: a331057 | Branch: fix/proxy-upgrade-no-downgrade

Задача infra-pm 2026-11-01: на hb-sites работает `…-ban10-gate9-…`, умолчание boks парка (c52f4f6b) —
`…-ban9-gate4-…`; `boks proxy upgrade` с бинаря парка молча откатил бы прокси. Отказывать, а не только
поднимать умолчание. Не входит: `DefaultProxyImage`, выкат образа на hb-sites (слово владельца).

## Validation Commands
- `go build ./... && go vet ./... && go test ./...` в корне

## Acceptance Criteria
- AC1: `proxy.Upgrade` отказывает, если тег запрошенного образа старше работающего по ban или gate, до
  pull, stop и записи в журнал.
- AC2: `boks proxy upgrade --force` ставит и такой образ; новее или с тегом без `banN` — как раньше.
- AC3: разбор тега: с реестром и digest, `-banN` без gate = gate0, чужой тег — без номеров.
- AC4: предупреждение `proxy boot` о другом образе называет его старшим и говорит про `--force`.
- AC5: мутации — выключенное сравнение и неразобранный `--force` — роняют тесты.

## Pipeline
- [x] 0 worktree
- [x] 1 план (issue #145)
- [x] 2 реализация
- [ ] 3 PR
- [ ] 4 review-loop green
- [ ] 5 merge
