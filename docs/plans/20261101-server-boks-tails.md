# Хвосты серверного boks (boks#164, после этапа 1b #154)

Цель: проверки до изменений сверяют тот конфиг, который потом загрузится, — собранный серверным boks; битый
серверный boks не подменяется тихой сборкой у вызывающего.

## Шаги
- [x] 1. `boks proxy-config check` отвечает конфигом кандидата: политика байтами `SetPolicy`, секреты
  (пароль egress, секреты гейта), маршруты (`CandidateConfig`). `assembleOf` — конфиг для проверок
  `SetPolicy`, `Reshape`/`validate` и `CheckServerBoks`. `CheckGate` собирает у вызывающего: `apply` зовёт его
  до установки сборки из `server.yml`, и спросить пришлось бы заменяемую. Пустой ответ — отказ; сборка 1b
  отказывает сама, на незнакомом поле `policy`. (#164 п.1)
- [x] 2. Ссылка `~/.boks/bin/boks`, которая есть и не запускается, — ошибка, а не «своего boks нет». (#164 п.3)
- [x] 3. `remote.Local` с `WaitDelay`, как SSH. (#164 п.5)
- [x] 4. Тесты и мутации (`internal/proxy/assemble_test.go`, `TestProxyConfigCheck`, ожидания выката и apply).
- [x] 5. `docs/architecture.md`, справка `boks`.
- [x] 6. PR через `/review-loop --ship`, merge — #166, `6f10e7c`.

Не в этом PR (остаются в #164): п.2 — проверка новой сборки по `policy.json` до смены ссылки в
`InstallBoks` (сейчас fail closed: выкаты отказывают до `server apply` с новым пином); п.4 — лишний
ssh-вызов на сборку (по мультиплексированному соединению, дёшево).

## Проверка
```
go build ./... && go vet ./... && test -z "$(gofmt -l cmd internal)" && go test ./...
(cd proxy/gate && go vet ./... && go test ./...)
```
