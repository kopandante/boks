# Приложения в состоянии сервера (boks#154, этап 2a)

Цель: `server apply` кладёт на серверы конфиги приложений из `server.yml` и их окружение; `server status`
показывает расхождение. Выкат по ним — этап 3.

## Шаги
- [x] 1. `server.yml` `apps: {<app>: <boks.yml>}`; требует `boks:`; имя — имя приложения, не `bin` (`internal/config/server.go`).
- [x] 2. `Server.LoadApps` — boks.yml целиком, пересечение серверов, `EnvContent`, токен реестра; `files`/`cert` — отказ; без секретов для status (`internal/config/apps.go`).
- [x] 3. `deploy.PutApps` под замком допуска — `~/.boks/_server/apps/<app>/{boks.yml,env,registry.token}` 0600, удаление лишнего; `deploy.AppsDrift` (`internal/deploy/apps.go`).
- [x] 4. `server apply`: приложения читаются до вопросов серверам, пишутся после boks и до политики; `server status` — строки расхождения (`cmd/boks/main.go`).
- [x] 5. Тесты (`internal/config/apps_test.go`, `internal/deploy/apps_test.go` на настоящем sh, два теста `cmd/boks`) и мутации — ловятся.
- [x] 6. `docs/architecture.md`.
- [ ] 7. PR через `/review-loop --ship`, merge.

## Проверка
```
go build ./... && go vet ./... && test -z "$(gofmt -l cmd internal)" && go test ./...
(cd proxy/gate && go vet ./... && go test ./...)
```

## Не здесь
- 2b: конфиги приложений и хэш окружения в истории ревизии, `server rollback` возвращает их.
- 3: `deploy-hook`, перенос `files`/`cert`.
