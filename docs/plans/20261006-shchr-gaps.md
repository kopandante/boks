# Пробелы boks на первом многокомпонентном проде (shchr) — 2026-10-06

Цель: конфигурация сервера shchr (Next.js, Convex, Logto, blanks, Postgres, nginx-редиректы)
выражается в `boks.yml` без обходов в образах приложений.

Автор, 2026-10-06: «Если в boks чего-то не хватает для работы реального приложения, значит надо
добавить.»

## Что не легло (сверка 2026-10-06 с живым сервером shchr)

| # | Компонент shchr | Чего нет в boks | Обход, который был бы нужен |
|---|---|---|---|
| G1 | Postgres 16 (общий, без маршрута) | Готовность без маршрута — только по `HEALTHCHECK` образа (A1); у `postgres:16` его нет | свой образ `FROM postgres:16` + `HEALTHCHECK` |
| G2 | nginx-редиректы (`nomination`, `report`) | Только именованные тома; конфиг nginx монтировался файлом с хоста | вшить конфиг в свой образ |
| G3 | kamal-proxy (все маршруты) | `proxy.Boot` не трогает работающий прокси: новый `proxy_image` молча игнорируется, обновить прокси нечем (D2 `server upgrade` не сделан) | остановить и пересоздать прокси руками |

Остальное ложится как есть: маршрут на порт (Logto — два порта на два домена), тома, `uses:`,
`replace: stop-first` (Convex), приватный реестр (GHCR — `registry:` с токеном на чтение),
wildcard `*.shchr.ru` через `cert.dns: selectelv2`. Команды контейнеров нигде не переопределены.

## Пересмотр A1

Было: «без `HEALTHCHECK` образа — понятный отказ». Стало: готовность без маршрута проверяется
health check контейнера — `HEALTHCHECK` образа или блок `healthcheck:` в `boks.yml`, который его
задаёт или заменяет. Отказ остаётся, когда нет ни того, ни другого. То же для зависимости `uses:`:
ей нужен health check контейнера, откуда бы он ни пришёл.

## Работы

- [x] **G1 `healthcheck:`** (PR feat/healthcheck)
  - [x] `healthcheck: {cmd, interval}` в конфиге: `cmd` — строка для `sh -c` (`--health-cmd`),
        `interval` — длительность, по умолчанию 5s (не 30s Docker: деплой ждёт первый ответ)
  - [x] `docker run` получает `--health-cmd` / `--health-interval` и `--health-start-period
        <deploy_timeout>` с `--health-start-interval <interval>`: без них Docker объявляет копию
        unhealthy после трёх неудач подряд (15 с при 5s), и деплой отказывал задолго до
        `deploy_timeout`; `interval` не меньше 1ms (минимум Docker)
  - [x] предпроверка «образ без HEALTHCHECK» отказывает, только если нет и блока
  - [x] снимок релиза — формат 5 с полем `healthcheck`; откат запускает копию с записанным
        (и отказывает до изменений, если записанный `interval` не короче сегодняшнего `deploy_timeout`)
  - [x] тексты отказов называют оба способа
  - [x] architecture.md, decisions A1
  - [x] проверка: `go test ./...` (мутации ключевых строк ловятся); boks-lab 2026-10-06, свежее приложение
        `pgcheck`: без блока — отказ до изменений; `postgres:16` + `pg_isready` → healthy, снимок v5;
        16→17 на томе 16 → unhealthy, новая копия снята, старая поднята; 16→16-bookworm→rollback → healthy
        с записанной проверкой по digest. Стенд убран
- [ ] **G2 `files:`** (PR feat/files, поверх G1)
  - [x] `files: ["<локальный путь>:/абсолютный/путь/в/контейнере"]`, путь от каталога `boks.yml`
  - [x] файлы релиза заливаются в `.boks/<app>/files/<release>/`, монтируются `:ro`
  - [x] права: каталог 0700 (на хосте недоступен другим), файл 0644 (читается пользователем
        контейнера любого uid) — проверить на свежем томе/каталоге, не на стенде
  - [x] снимок — формат 6 с `files`; откат монтирует файлы своего релиза и отказывает, если их нет
  - [x] Prune удаляет файлы релиза вместе со снимком
  - [x] проверка: `go test ./...` (мутации ключевых строк ловятся, в т.ч. сбой chmod); boks-lab 2026-10-06,
        свежее приложение: nginx-unprivileged (uid 101) читает конфиг (301 по правилу из файла),
        каталоги 700, файл 644, в контейнере `:ro` — запись `Permission denied`. Стенд убран

- [ ] **G3 обновление прокси** (решение по форме — за автором: часть D2 `server upgrade` или
      отдельная `boks proxy upgrade`; 80/443 держит один контейнер, замена образа = короткий разрыв)

## Сверка habsida и tokyo (2026-10-06) — пробелы того же рода

| # | Что | Кого блокирует | Статус |
|---|---|---|---|
| G4 | Переопределение command/args | 8 Redis (`redis-server --requirepass …`, AOF у mail-redis) | **сделано** (feat/run-options): `command:` exec-форма, снимок v7; boks-lab: redis с паролем из env через `sh -c`, откат по digest с записанной командой |
| G5 | `--path-prefix` в `ports:` (kamal-proxy умеет, boks не выставляет) | pakim `/api/cn/images` → шлюз (перезапись пути и заголовки — в коде шлюза) | **сделано** поверх Caddy (C2–C3, feat/caddy-routes): `path`, `strip_path`/`path_rewrite`, `headers`, снимок v9 |
| G6 | Расписания | auctions (`warm_namsuwon_catalog` каждые 4 мин) | **сделано** (feat/schedules): cron хоста + `boks-job`, снимок v8 (разбор codex: не контейнер-планировщик) |
| G7 | Wildcard-хост `*.домен` | onestar (`cars-*.buying-korea.com`) | **сделано** поверх Caddy (C4): `*.домен` на одну метку, точные хосты раньше; `cars-*` внутри метки Caddy не матчит — onestar берёт `*.buying-korea.com`, чужие поддомены — точными хостами |
| G8 | `stop_signal` | Convex-стеки (Dokploy шлёт SIGINT) | **сделано** (feat/run-options): `stop_signal:` → `--stop-signal`, в снимке v7 |
| G9 | Фильтр по User-Agent на весь сервер | bot-policy Habsida | **сделано** поверх Caddy (C5, feat/server-policy): `server.yml` + `boks server apply/rollback/status`, `bots.allow`/`bots.block` |

Телеметрия (решение автора 2026-10-06): центр (Grafana, Prometheus, Loki) — на отдельном сервере, это
обычные приложения boks. Сборщики на каждом сервере — вне boks (systemd), privileged/docker.sock в
boks не нужны.

## Критерий готовности

shchr описывается шестью `boks.yml` без своих образов-обёрток; оба PR влиты через `/review-loop`.
