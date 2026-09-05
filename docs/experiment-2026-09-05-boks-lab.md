# Стенд kamal-proxy на boks-lab — 2026-09-05

Машина: OCI `boks-lab` (152.70.59.137), Ampere ARM aarch64, 2 ядра / 12 GB, Ubuntu 24.04,
Docker 29.8. kamal-proxy **v0.10.0** (образ `basecamp/kamal-proxy:v0.10.0`, есть arm64).
Приложение: self-hosted Convex `ghcr.io/get-convex/convex-backend:latest` (arm64 есть, образ
796 MB) — порты 3210 (API) и 3211 (HTTP actions). Стенд оставлен работающим.

## Итоги по пунктам

| # | Пункт | Результат | Число / факт | Вывод для boks |
|---|---|---|---|---|
| 1 | kamal-proxy standalone, флаги | ✅ | `run`, `deploy`, `remove`, `list`; state в `/home/kamal-proxy/.config/kamal-proxy/kamal-proxy.state` + `certs/`; есть `--tls-staging`, `--tls-acme-cache-path`, `--health-check-{path,port,timeout,interval}`, `--deploy-timeout` (30s), `--drain-timeout` (30s), `--target-timeout` (30s), `--force`, `--path-prefix`, `--canonical-host` | Kamal-gem не нужен: весь lifecycle — четыре подкоманды через `docker exec` |
| 2 | Двухпортовое приложение | ✅ | Convex healthy через ~4 с; `/version` отвечает на ОБОИХ портах, различаются по `/`: 3210 → «This Convex deployment is running» [200], 3211 → «does not have HTTP actions enabled» [404] | Health check для actions — через `--health-check-port 3210` |
| 3 | Multi-port: 2 сервиса → 1 контейнер | ✅ | `boks-api`→`:3210` под `api.lab.kopanda.ru`, `boks-actions`→`:3211` под `actions.lab.kopanda.ru`; маршруты различимы; неизвестный host → 404 | Кейс Convex закрывается двумя `deploy`, без compose |
| 4a | autocert HTTP-01 (LE production) | ✅ | `deploy --tls` без сертификатов → HTTPS отвечает через **5 с**, issuer `Let's Encrypt YE1`, HTTP→HTTPS 301 | Обычные домены — ноль конфигурации |
| 4b | wildcard DNS-01 (LE staging) | ✅ с оговоркой | `lego` **с ноутбука** (v5.2.2, все флаги на `run`); с сервера — `CF_GOD_TOKEN` IP-restricted: «Cannot use the access token from location: 152.70.59.137 (9109)»; cert `CN=*.lab.kopanda.ru` подан через `--tls-certificate-path/--tls-private-key-path`, openssl показывает именно его | Выпуск wildcard — операция ноутбука/CI, не сервера; серверу нужен только файл. Совпадает с моделью «boks на ноутбуке» |
| 5 | Zero-downtime v1→v2 под нагрузкой | ✅ | api: 290 запросов, **0 ошибок**; actions: 324, **0 ошибок**; `stop v1` под нагрузкой: 163, 0; `deploy` — **0.05–0.07 с** при уже здоровой цели; rollback на v1 — 0.05 с | `boks deploy` = run new → `deploy` → stop old; rollback = тот же `deploy` на старый контейнер |
| 6 | Рестарт прокси под HTTPS-нагрузкой | ⚠️ секунды → доли секунды | `docker restart` 0.32 с; 312 запросов, **4 ошибки в окне 0.19 с**; маршруты и TLS (autocert-сертификат, ACME-аккаунт) пережили рестарт из volume | Простой при обновлении прокси — ~0.2 с, приемлемо; state обязан жить в volume |
| 7 | Ротация сертификата | ⚠️ нужен redeploy или restart | Подмена файлов без `deploy` → отдаётся **старый** (загружен в память при deploy); повторный `deploy` с теми же флагами → новый; `docker restart` → перечитывает файлы по путям из state (PEM в state нет) | Продление wildcard = положить файлы + повторить `deploy` (0.05 с, без простоя) |
| 8 | RSS | ✅ | `boks-proxy` anon: **2.0 MB** пустой, 7.0 MB после TLS+нагрузки, 2.1 MB после рестарта; Convex ~12 MB anon каждый; `free`: used 466 MB (пустой Docker) → 639–641 MB (прокси + 2 Convex); `dockerd` 112 MB | Вместо ~850 MB Node-процесса Dokploy — единицы мегабайт |

**Главный вывод: kamal-proxy годится**, с двумя оговорками: (1) ротация своих сертификатов —
через повторный `deploy` (0.05 с, без потерь), автоматически он файлы не перечитывает;
(2) рестарт прокси = ~0.2 с недоступности, что для обновления самого прокси приемлемо.

## Команды, которые сработали (основа `boks deploy`)

```bash
# прокси (один раз на сервер)
docker network create boks-test
docker volume create boks-proxy-config; docker volume create boks-certs
docker run -d --name boks-proxy --restart unless-stopped --network boks-test \
  -p 80:80 -p 443:443 \
  -v boks-proxy-config:/home/kamal-proxy/.config/kamal-proxy \
  -v boks-certs:/certs basecamp/kamal-proxy:v0.10.0

# приложение (контейнер с версией в имени, в той же сети)
docker run -d --name boks-app-v1 --network boks-test -v boks-convex-v1:/convex/data \
  -e INSTANCE_NAME=... -e INSTANCE_SECRET=... \
  -e CONVEX_CLOUD_ORIGIN=https://api.lab.kopanda.ru -e CONVEX_SITE_ORIGIN=https://actions.lab.kopanda.ru \
  -e DISABLE_BEACON=true -e DO_NOT_REQUIRE_SSL=true ghcr.io/get-convex/convex-backend:latest

# маршруты: один deploy на порт/домен; deploy сам ждёт health check и переключает
docker exec boks-proxy kamal-proxy deploy boks-api --target boks-app-v1:3210 \
  --host api.lab.kopanda.ru --tls --health-check-path /version --deploy-timeout 60s
docker exec boks-proxy kamal-proxy deploy boks-actions --target boks-app-v1:3211 \
  --host actions.lab.kopanda.ru --tls \
  --tls-certificate-path /certs/wild/_.lab.kopanda.ru.crt --tls-private-key-path /certs/wild/_.lab.kopanda.ru.key \
  --health-check-port 3210 --health-check-path /version --deploy-timeout 60s

# новая версия: поднять v2, переключить, остановить v1 (0 ошибок под нагрузкой)
docker run -d --name boks-app-v2 ... ; docker exec boks-proxy kamal-proxy deploy boks-api --target boks-app-v2:3210 ...
docker stop boks-app-v1
# rollback = тот же deploy на boks-app-v1:3210

# wildcard (с ноутбука/CI; lego v5 — все флаги на run)
CLOUDFLARE_DNS_API_TOKEN=... lego run --server https://acme-staging-v02.api.letsencrypt.org/directory \
  --path ./lego --accept-tos --email <email> --dns cloudflare --domains '*.lab.kopanda.ru'
# → scp .crt/.key на сервер → в volume с owner 1001:1001 (uid kamal-proxy), mode 640 → повторный deploy
```

Файлы сертификатов внутри volume должны принадлежать uid **1001** (`kamal-proxy`) — volume
создаётся root-овым, без `chown` прокси их не прочитает.

## Что не сработало и почему

- `goacme/lego:latest` (v5.4.1) и локальный lego 5.2.2: старый синтаксис `lego --accept-tos
  --email … run` → «flag provided but not defined». В v5 `--accept-tos`, `--email`, `--dns`,
  `--domains`, `--server`, `--path` — флаги подкоманды `run`.
- DNS-01 с сервера: `CF_GOD_TOKEN` ограничен по IP (ошибка 9109 с 152.70.59.137), с ноутбука
  работает — и читает, и пишет DNS в `kopanda.ru` (заметка в skill server/oci.md о том, что
  `cfat_`-токен не работает с DNS-записями, для этого токена неверна). Для прода: завести
  zone-scoped токен без IP-ограничения (или с IP build/CI-хоста) и провайдер `selectel` в lego
  для зоны Shchr — там Traefik уже доказал Selectel DNS-01 (Traefik использует lego внутри).
- `kamal-proxy --version` — флага нет; версия только по тегу образа.

## DNS-записи (Cloudflare, зона kopanda.ru `49389ef49e23105002ecaf4f35bcab5a`, DNS only, TTL 120)

| Имя | ID | |
|---|---|---|
| lab.kopanda.ru | 43aa99e273d327c76ed3556a64e6614d | создана |
| api.lab.kopanda.ru | 154efcca5c2c6ec10b753270d8817bfc | создана; LE production cert выпущен |
| actions.lab.kopanda.ru | 5ac1e91a787835693a950d925f3f4f11 | создана |

## Уборка

```bash
# на boks-lab
docker rm -f boks-proxy boks-app-v1 boks-app-v2
docker volume rm boks-proxy-config boks-certs boks-convex-v1 boks-convex-v2
docker network rm boks-test
docker rmi basecamp/kamal-proxy:v0.10.0 ghcr.io/get-convex/convex-backend:latest goacme/lego:latest goacme/lego:v4.21.0 alpine
rm -rf /home/ubuntu/{exp*.sh,postboot.sh,wild,*.log,convex-secret.txt}
# DNS (с ноутбука, CF_GOD_TOKEN)
for id in 43aa99e273d327c76ed3556a64e6614d 154efcca5c2c6ec10b753270d8817bfc 5ac1e91a787835693a950d925f3f4f11; do
  curl -s -X DELETE -H "Authorization: Bearer $CF" https://api.cloudflare.com/client/v4/zones/49389ef49e23105002ecaf4f35bcab5a/dns_records/$id; done
```
