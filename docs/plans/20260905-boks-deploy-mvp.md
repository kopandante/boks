# boks deploy MVP (Go) — план

Цель: `boks deploy <tag>` с ноутбука разворачивает приложение из готового образа на сервере
через Docker + kamal-proxy без простоя; проверено на `boks-lab` с Convex на двух портах.
Архитектура — `docs/architecture.md` (v2), команды-основа — `docs/experiment-2026-09-05-boks-lab.md`.

## Скоуп v0.1

- [ ] Go-модуль `github.com/kopandante/boks`, layout `cmd/boks` + `internal/*`, зависимости: stdlib + `gopkg.in/yaml.v3`
- [ ] `internal/config`: `boks.yml` (app, image, servers, network, proxy_image, env/env_file, volumes, ports[], tls, keep, deploy_timeout), дефолты, валидация, `EnvContent()`; тесты
- [ ] `internal/remote`: `Runner` (Run/Upload), `SSH` через системный `ssh` (уважает `~/.ssh/config`), shell-quoting
- [ ] `internal/proxy`: `Boot` (сеть, volumes, контейнер `boks-proxy`, идемпотентно), `DeployArgs`, `List`; тесты
- [ ] `internal/deploy`: lock → pull → run (`<app>-<tag>-<unix>`, лейблы boks.app/boks.version) → `kamal-proxy deploy` на каждый порт → retire старых → prune образов до `keep`; при провале переключения старый продолжает обслуживать; тесты на FakeRunner
- [ ] `cmd/boks`: `deploy TAG | rollback TAG | ps | proxy boot|list | unlock`, флаг `-f`
- [ ] `examples/convex-lab/boks.yml` без секретов (`.env` в `.gitignore`)

Вне скоупа v0.1: preview, db-провижининг, wildcard/lego, bws, webhook-приёмник,
параллельный обход серверов, `boks logs`.

## Проверка

```
go vet ./... && go test ./... && test -z "$(gofmt -l .)"
go build -o boks ./cmd/boks
```

На `boks-lab` (стенд от эксперимента занимает те же хосты — сначала снять его сервисы):

```
ssh boks-lab 'docker exec boks-proxy kamal-proxy remove boks-api; docker exec boks-proxy kamal-proxy remove boks-actions; docker stop boks-app-v1 boks-app-v2'
./boks -f examples/convex-lab/boks.yml proxy boot        # второй запуск — без изменений
./boks -f examples/convex-lab/boks.yml deploy latest
curl -s https://api.lab.kopanda.ru/version               # 200, версия Convex
curl -s -o /dev/null -w '%{http_code}' https://actions.lab.kopanda.ru/   # 404 «HTTP actions»
./boks -f examples/convex-lab/boks.yml ps
# под curl-циклом на /version (50 мс, 20 с):
./boks -f examples/convex-lab/boks.yml deploy latest     # повторный деплой той же версии = новый контейнер, 0 ошибок
./boks -f examples/convex-lab/boks.yml rollback latest   # без pull, 0 ошибок
ssh boks-lab 'mkdir /tmp/boks-convex-lab.lock'; ./boks ... deploy latest   # понятная ошибка
./boks -f examples/convex-lab/boks.yml unlock
```

## Критерии готовности

- [ ] все проверки выше зелёные на `boks-lab`; в curl-цикле 0 ошибок при deploy и rollback
- [ ] секреты из env-файла не появляются в выводе `boks` и в сообщениях об ошибках
- [ ] `/review-loop` зелёный
