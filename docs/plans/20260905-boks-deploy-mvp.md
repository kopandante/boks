# boks deploy MVP (Go) — план

Цель: `boks deploy <tag>` с ноутбука разворачивает приложение из готового образа на сервере
через Docker + kamal-proxy без простоя; проверено на `boks-lab` с Convex на двух портах.
Архитектура — `docs/architecture.md` (v2), команды-основа — `docs/experiment-2026-09-05-boks-lab.md`.

## Скоуп v0.1

- [x] Go-модуль `github.com/kopandante/boks`, layout `cmd/boks` + `internal/*`, зависимости: stdlib + `gopkg.in/yaml.v3`
- [x] `internal/config`: `boks.yml` (app, image, servers, network, proxy_image, env/env_file, volumes, ports[], tls, keep, deploy_timeout), дефолты, валидация, `EnvContent()`; тесты
- [x] `internal/remote`: `Runner` (Run/Upload), `SSH` через системный `ssh` (уважает `~/.ssh/config`), shell-quoting
- [x] `internal/proxy`: `Boot` (сеть, volumes, контейнер `boks-proxy`, идемпотентно), `DeployArgs`, `List`; тесты
- [x] `internal/deploy`: lock → pull → run (`<app>-<tag>-<unix>`, лейблы boks.app/boks.version) → `kamal-proxy deploy` на каждый порт → retire старых → prune образов до `keep`; при провале переключения старый продолжает обслуживать; тесты на FakeRunner
- [x] `cmd/boks`: `deploy TAG | rollback TAG | ps | proxy boot|list | unlock`, флаг `-f`
- [x] `examples/convex-lab/boks.yml` без секретов (`.env` в `.gitignore`)

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

- [x] все проверки выше зелёные на `boks-lab` (2026-09-05): `proxy boot` идемпотентен; `/version` 200, actions 404, http→https 301, оба хоста с production-сертификатами Let's Encrypt; deploy под нагрузкой — 796 запросов, **0 ошибок**; rollback — 656, **0 ошибок**; старый контейнер удалён; lock даёт понятную ошибку, `unlock` снимает; при несуществующем теге деплой падает на pull и lock освобождается
- [x] секреты из env-файла не появляются в выводе `boks` и в сообщениях об ошибках (grep значения `INSTANCE_SECRET` по всему выводу — 0 совпадений)
- [x] `/review-loop` зелёный — **с деградацией гейта**: внешняя панель не участвовала (codex — usage limit до 2026-09-07; grok — исключён директивой автора; `/verify` — только ручной вызов), раунды держал только agent (`diff-review`), tier=full, два чистых прохода подряд после раунда 1. Раунд 1: 1 существенная находка (частичное переключение маршрутов при провале второго порта → откат уже переключённых маршрутов, коммит `03578ae`) + 2 мелких (валидация `deploy_timeout`, текст usage). Повторный e2e на `boks-lab` после правок — зелёный. Известное ограничение: при ДВУХ и более предыдущих контейнерах (висящий остаток прошлого провала) автоматический откат маршрутов невозможен — boks предупреждает и называет контейнеры.

## Замечено, вне скоупа v0.1

- Полный `deploy` занимает 40–55 с при переключении за 0.05 с: ожидание health Convex (~4 с),
  `docker stop` с 10-секундным grace для старого контейнера и отдельное ssh-соединение на каждую
  команду (~10 команд). Оптимизация: ssh ControlMaster/одна сессия, `--stop-timeout` в конфиге.
