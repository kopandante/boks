# Выкат по ключу сайта: deploy-hook (boks#154, этап 3)

Цель: CI сайта выкатывает своё приложение одной командой `ssh <server> <tag>` по ключу, который ничего
другого не умеет; выкатывает серверный boks по файлам, которые положил `server apply`.

## Шаги
- [x] 1. `server.yml` `deploy_keys`, строгая проверка ключа (`internal/config/deploykey.go`).
- [x] 2. Блок `authorized_keys` в `server apply` после приложений, чужие строки байт в байт (`internal/deploy/keys.go`).
- [x] 3. `boks deploy-hook <app>`: тег из `SSH_ORIGINAL_COMMAND` строго, файлы сервера, `deploy.Run` через `remote.Local` (`cmd/boks/main.go`).
- [x] 4. Тесты: инъекции в тег, выкат по файлам сервера, чужой boks.yml, блок ключей (сохранение, замена, снятие, отказы), порядок в apply, откат без приложений; мутации — ловятся.
- [x] 5. `docs/architecture.md`.
- [ ] 6. PR через `/review-loop --ship`, merge.

## Проверка
```
go build ./... && go vet ./... && test -z "$(gofmt -l cmd internal)" && go test ./...
(cd proxy/gate && go vet ./... && go test ./...)
```

## Не здесь
- Пилот на сайте и перевод сайтов (этап 4) — по слову владельца.
- `files`/`cert` приложения на сервере — когда понадобятся первому сайту.
- Ключи в `server status`.
