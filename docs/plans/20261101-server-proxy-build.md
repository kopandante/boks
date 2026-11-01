# Конфиг прокси собирает серверный boks (boks#154, этап 1b)

Цель: на сервере со своим boks (`~/.boks/bin/boks`, этап 1a, #159) конфиг Caddy собирает он — той версии,
что в `server.yml`, — какой бы boks ни запустил выкат, `server apply` или `proxy upgrade`.

## Шаги
- [x] 1. `remote.Local` — Runner без ssh, из домашнего каталога (`internal/remote/local.go`).
- [x] 2. `proxy.assemble` — одна сборка для `reconverge`/`Validate`/`Lags`: есть серверный boks — фрагменты ему
  на stdin, конфиг — его ответ; отказ — отказ; нет — сборка у вызывающего (`internal/proxy/assemble.go`).
- [x] 3. `proxy.ServerConfig` + команда `boks proxy-config` (без boks.yml и ssh): политика и маршруты строго,
  секреты с диска (`cmd/boks/main.go`).
- [x] 4. Тесты: `internal/proxy/assemble_test.go`, `internal/remote/local_test.go`,
  `TestProxyConfigFromTheHome`; ожидания вызовов выката (`internal/deploy/deploy_test.go`). Мутации
  `assemble.go` (строгость, делегирование, перевод строки, откат на локальную сборку) — ловятся.
- [x] 5. `docs/architecture.md`.
- [x] 6. Ревью: `server apply`/`rollback` спрашивают серверный boks о новой политике до `Reshape`
  (`proxy.CheckServerBoks`, `boks proxy-config check`) — иначе отказ строгого чтения приходил после
  пересоздания прокси под новую форму (`TestApplyServerAsksTheServersBoksBeforeTheSwap`).
- [ ] 7. PR через `/review-loop --ship`, merge.

## Проверка
```
go build ./... && go vet ./... && test -z "$(gofmt -l cmd internal)" && go test ./...
(cd proxy/gate && go vet ./... && go test ./...)
```

## Готово
- Сервер со своим boks: конфиг, который грузится в Caddy, собирает `boks proxy-config`, а не вызывающий —
  `assemble` не читает `policy.json` (`TestAssembleAsksTheServersBoks`); проверки до изменений (хосты, правило
  гейта) по-прежнему читают её у вызывающего.
- Политику, которую серверный boks не читает, `server apply` отвергает до любых изменений.
- Незнакомое поле в политике или маршрутах — отказ серверного boks с советом `server apply`.
- Сервер без своего boks — поведение и вызовы прежние (существующие тесты выката зелёные).
- На серверы ничего не выкатывается: серверный boks на прод-узлах — по слову владельца.
