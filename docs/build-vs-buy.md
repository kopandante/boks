# Build-vs-buy: готовые инструменты против требований boks

Дата: 2026-09-05. Источник: официальная документация кандидатов (проверено по докам там, где
помечено **(док)**; **(оценка)** — оценка рецензента). Кандидаты: Kamal 2 + kamal-proxy
(Basecamp), Dokku, Uncloud (найден по ходу, живой, но ранний), «Caddy + systemd + скрипт» как
нулевой вариант. Coolify не рассматривался — тяжелее Dokploy.

Легенда: ✅ есть / ⚠️ частично или обходным путём / ❌ нет.

| # | Требование | Kamal 2 + kamal-proxy | Dokku | Uncloud | Caddy + systemd + скрипт |
|---|---|---|---|---|---|
| 1 | Что живёт на app-сервере, RSS | Только `kamal-proxy` (один Go-бинарник в контейнере) + Docker. Ruby — только на ноутбуке/CI (док: installation). RSS ~10–20 MB (оценка) | nginx (или Caddy-контейнер через плагин) + bash/Go-инструменты dokku без постоянного демона (кроме мелкого event-listener — оценка) + Docker. Мин. 1 GB RAM (док: installation). ~30–60 MB (оценка) | `uncloudd` (Go-демон, systemd) + `corrosion` (CRDT-SQLite от Fly, Rust) + WireGuard + Caddy-контейнер (док: README §How it works). ~100–200 MB (оценка) | Caddy (~30–60 MB, оценка) + Docker. Больше ничего |
| 2 | Деплой готового образа из GHCR без сборки | ✅ `kamal deploy -P --version=TAG` — «Skip image build and push» + версия (док: commands/deploy) | ✅ `git:from-image app image:tag`, также `git:load-image` без registry (док: deployment/methods/image) | ✅ `uc run image` / compose; плюс Unregistry — push слоёв прямо на машину без registry (док: README) | ✅ `docker pull` в скрипте |
| 3 | Сборка на отдельном build-сервере | ✅ `builder.remote: ssh://docker@builder` (док: configuration/builders) или любой CI → registry | ✅ собираешь где угодно → `git:from-image` | ✅ Unregistry / любой CI | ✅ тривиально |
| 4 | Несколько портов на одно приложение, каждый на свой домен/TLS | ⚠️ kamal-proxy: один host → один `target host:port`, «только один сервис на host» (док: kamal-proxy README). Второй домен → второй порт того же контейнера: либо второй role (= второй контейнер того же образа, у role свой `proxy.host`/`app_port`, док: configuration/proxy), либо ручной `kamal-proxy deploy svc2 --target same-container:3211 --host b.example.com` в post-deploy hook (оценка) | ⚠️ `ports:add` мапит порты, но на **все** домены приложения (док: port-management); домен→порт — только кастомный `nginx.conf.sigil` (док упоминает шаблон) | ⚠️ `-p host:port/https` на публикацию; несколько `-p` для одного сервиса — вероятно да (оценка), не подтверждено доком | ✅ Caddyfile: два `reverse_proxy` на два хоста |
| 5 | ACME DNS-01 / wildcard (Selectel) | ❌ нативно: `--tls` = autocert, только HTTP-01/TLS-ALPN (док: kamal-proxy README «Automatic TLS», без упоминания DNS). ⚠️ Обход: `proxy.ssl.certificate_pem/private_key_pem` из secrets (док: configuration/proxy «Custom SSL certificate») + внешний lego по cron (lego знает `selectel`/`selectelv2`, док: lego DNS providers) | ✅ dokku-letsencrypt: `dns-provider` переключает на DNS-01 и даёт wildcard, под капотом lego (док: README); Selectel в lego есть (док). **Но** Caddy-плагин Dokku «поддерживает только свой letsencrypt, certs игнорирует» (док: proxies/caddy) — DNS-01 только с nginx | ❌ Caddy внутри — свой ACME, DNS-провайдеры Caddy не проброшены (оценка); managed wildcard только `*.xxx.uncld.dev` (док: README) | ⚠️ Caddy DNS-01 требует сборку Caddy с DNS-модулем; модуля Selectel в `caddy-dns` может не быть (оценка) → тогда lego + Caddy `tls cert key` |
| 6 | Zero-downtime + rollback | ✅ health check `/up` → переключение → drain старого (док: deploy, kamal-proxy README); `kamal rollback VERSION` (док) | ✅ CHECKS/`app.json` healthchecks, `wait-to-retire` (док: zero-downtime-deploys). Rollback: нативной команды нет (оценка) — передеплой старого тега | ⚠️ rolling updates ✅; «Automatic rollback on failure is coming soon» (док: README) | ⚠️ Caddy admin API умеет менять upstream без рестарта ✅; логику health→switch→drain пишешь сам |
| 7 | Preview на PR: домен + база + teardown | ❌ нативно нет; `destinations` (`-d staging`) — отдельный конфиг, не PR-автоматика (док: hooks/overview упоминает `KAMAL_DESTINATION`). Скриптуется через CI + hooks (оценка) | ⚠️ `apps:clone` + скрипт из CI (оценка); нативных review apps нет | ❌ | ❌ пишешь сам |
| 8 | Один Postgres на сервер, database на приложение | ⚠️ accessories = контейнеры, «managed separately, no zero-downtime» (док: configuration/accessories). Один общий accessory ✅, а `CREATE DATABASE` на приложение — сам, в hook | ⚠️ dokku-postgres = контейнер на service; один service можно `link` к многим apps, но это **одна** база (док: README, `postgres:links`); db-per-app — руками SQL | ❌ только compose-сервисы | ⚠️ `psql -c 'CREATE DATABASE …'` в скрипте |
| 9 | Деплой по webhook GitHub | ❌ на сервере приёмника нет. ✅ через CI: `kamal deploy` в GitHub Actions на push (стандартный путь) | ❌ приёмника нет; ✅ через CI (`git push dokku` из Actions) | ❌ | ❌ пишешь мини-приёмник |
| 10 | API/CLI с токеном | ⚠️ только CLI по SSH-ключам, HTTP API нет (док: ssh) | ⚠️ `ssh dokku@host cmd` по ключам (док: remote-commands), HTTP API нет | ⚠️ CLI `uc` → gRPC к `uncloudd` через WireGuard/SSH (оценка) | ❌ |
| 11 | Логи → Loki на другом инстансе | ✅ `logging.driver`/`options` → Docker loki-driver или journald→Alloy (док: configuration/logging) | ✅ `logs:set vector-sink loki://…` — встроенный Vector-shipping (док: deployment/logs) | ⚠️ Docker log-driver руками (оценка) | ✅ Docker log-driver |
| 12 | Обновление инструмента без простоя прокси | ⚠️ `kamal upgrade`/`proxy reboot` перезапускает kamal-proxy; «без простоя» только rolling по нескольким хостам (док: upgrading «Avoiding downtime») — на одном сервере секунды простоя | ✅ nginx reload graceful; обновление dokku не трогает прокси (оценка) | ⚠️ Caddy-контейнер пересоздаётся (оценка) | ✅ Caddy graceful reload |
| 13 | Секреты не утекают | ✅ `.kamal/secrets` + адаптеры 1Password/LastPass/Bitwarden (док: commands/secrets); в контейнер через env-file. Есть `kamal secrets print` «for debugging» — не вызывать (док) | ⚠️ `config:show` печатает значения в открытую (док: environment-variables) | ⚠️ compose env (оценка) | зависит от скрипта |
| 14 | Независимые серверы, без control-plane | ✅ Kamal stateless, состояние — на хостах и в registry; список серверов в `deploy.yml` (док: servers) | ✅ каждый хост автономен | ⚠️ модель «кластер» с gossip-состоянием (corrosion), центрального узла нет, но серверы связаны (док) | ✅ |
| 15 | Без сборок на слабом сервере | ✅ сборка локально/CI/remote builder, сервер только pull (док) | ✅ с `git:from-image`; по умолчанию собирает на сервере | ✅ | ✅ |

## Что всё равно пришлось бы написать поверх

- **Kamal:** (a) второй host на второй порт одного контейнера — post-deploy hook с
  `kamal-proxy deploy` или второй role; (b) lego по cron для Selectel DNS-01 + подстановка PEM
  в secrets; (c) hook `CREATE DATABASE`/роль на приложение против общего Postgres-accessory;
  (d) GitHub Actions workflow «push → kamal deploy» и PR-preview через `-d pr-123` + teardown;
  (e) при желании — тонкий HTTP-приёмник вебхуков, если CI не устраивает. Всё это — сотни строк
  bash/YAML, не платформа.
- **Dokku:** (a) кастомный `nginx.conf.sigil` для домен→порт; (b) SQL-провижининг database на
  приложение поверх одного postgres-service; (c) CI-workflow для push и review-apps через
  `apps:clone`; (d) дисциплина вокруг `config:show`. Минус: нельзя одновременно Caddy-плагин и
  DNS-01.
- **Uncloud:** DNS-01, Postgres, previews, rollback, webhook — всё; плюс он тяжелее по RSS и
  тянет WireGuard-кластер, который не нужен.
- **Caddy + скрипт:** всё, кроме TLS и роутинга — это и есть «boks-lite» на 300–500 строк.

## Статус проектов (gh api, 2026-09-04)

Kamal v2.12.0 (2026-06-18), Ruby, MIT, push 2026-09-02, 14.5k★; kamal-proxy v0.10.0, Go, MIT,
push 2026-09-04, 1.1k★. Dokku v0.38.27 (2026-08-12), Shell+Go, MIT, push 2026-09-04, 32k★.
Uncloud v0.20.0 (2026-06-26), Go, Apache-2.0, push 2026-09-04, 5.5k★ — живой, но ранний
(rollback «coming soon»).

## Дополнение 2026-09-05: kamal-proxy без Kamal (ответ на «Ruby smells»)

Ruby в Kamal живёт только на ноутбуке оператора и в CI; на сервере — `kamal-proxy` (Go) и
Docker. Но сам Kamal (gem) не обязателен: **kamal-proxy — самостоятельный инструмент со своим
CLI**, подтверждено README:

- `kamal-proxy run [--http-port N ...]` — запуск прокси-демона.
- `kamal-proxy deploy <service> --target <host:port> --host <domain> [--tls]` — регистрация
  маршрута; `deploy` сам ждёт health check цели (`--health-check-path/-port/-timeout/-interval`)
  и только потом переключает трафик — zero-downtime встроен в команду.
- `--tls --tls-certificate-path cert.pem --tls-private-key-path key.pem` — свои сертификаты,
  т.е. wildcard от `lego` (DNS-01 Selectel) подключается напрямую.
- Host-based routing: несколько сервисов на одном прокси, один host → один сервис; `remove`.

Следствие для пункта 4 (два порта одного контейнера под двумя доменами): без Kamal это два
вызова — `deploy convex-api --target c:3210 --host api.x` и `deploy convex-actions --target
c:3211 --host actions.x`. Препятствием была абстракция Kamal «одно приложение = один target»,
а не прокси.

Что делает Kamal-gem поверх прокси и что пришлось бы написать самим в boks-CLI: ssh на хост,
`docker pull`/`run` новой версии, `kamal-proxy deploy`, остановка старой; плюс обвязка —
lock от параллельных деплоев, учёт версий для rollback (хранить N старых образов), hooks,
секреты (из bws напрямую), accessories (свой образ Postgres), конфиг log-driver → Loki, preview
(`CREATE DATABASE … TEMPLATE` + host + teardown), опциональный webhook-приёмник. Честная
оценка объёма при паритете с Kamal по аккуратности — 1.5–3k строк, дни–пара недель; язык
свободен (Go — ближе к экосистеме Docker/kamal-proxy; Rust — приемлемо; bash — для v0).

## Вердикт рецензента

По главному критерию — footprint на сервере — Kamal уже даёт то, ради чего задуман boks: на
сервере остаётся один маленький Go-прокси и Docker, ничего больше (док), и это закрывает
требования 1, 2, 3, 6, 11, 14, 15 из коробки, а 9 — стандартным CI-workflow. Ни один готовый
инструмент не закрывает нативно три вещи: домен-на-порт одного контейнера (4), DNS-01 с Selectel
внутри самого прокси (5 — у Kamal через внешний lego + custom cert, у Dokku ✅ но только с nginx)
и database-на-приложение в общем Postgres (8) — и все три это hook/скрипт, а не причина писать
Rust-ядро, Pingora и плагинную систему. Dokku — запасной вариант, если DNS-01 «из коробки»
важнее минимального RSS и есть готовность к nginx. Писать boks с нуля как платформу не
оправдано; оправдано «Kamal + обвязка» (hooks, lego-cron, psql-провижининг, Actions-workflow) —
и, если захочется, тонкий CLI/скрипт вокруг этого под именем boks. Проверить это можно за день:
задеплоить через Kamal самый неудобный реальный кейс — Convex-бэкенд с :3210/:3211 под двумя
доменами и wildcard-сертификатом — и посмотреть, приемлем ли обход для пункта 4.
