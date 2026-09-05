# Замеры памяти на серверах Dokploy — 2026-09-05

Read-only снятие с Habsida, Bravo, Shchr, Tokyo, OCI. Office пропущен (нет SSH).

**Метод.** cgroup v2 `memory.stat` каждого контейнера: `anon` (реальная невытесняемая память),
для Postgres отдельно `shmem` (там живут `shared_buffers`). `docker stats` / `memory.current`
для Postgres сильно завышает: на Habsida 5 app-Postgres показывают 5857 MB «current», из них
реальных (anon+shmem) — 557 MB, остальное — page cache файлов данных. Ниже везде anon (+shmem
для Postgres).

## Таблица (MB)

| Сервер | RAM | used | (a) Dokploy control-plane | (b) app Postgres | (c) app Redis | (d) приложения | telemetry | (e) хост вне контейнеров |
|---|---|---|---|---|---|---|---|---|
| Habsida | 24033 | 11744 | **859 (4%)** — node 781, traefik 58, pg 20+14sh, redis 0 | 5 шт / **557** (anon 48 + shmem 509) | 7 шт / 1137 (из них ОДИН `redis-calculate-digital-feed` = 1113 — данные) | 63 шт / 6125 | 6 шт / 521 | 3054 (dockerd **627**, containerd 52, 85 shim) |
| Bravo | 5925 | 3011 | **948 (16%)** — node 902, traefik 32, pg 11+15sh, redis 3 | 1 / 10 | 1 / 1 | 10 / 928 | — | 1131 (dockerd **457**, containerd 32, 16 shim) |
| Shchr | 3919 | 2355 | **866 (22%)** — node 814, traefik 40, pg 5+16sh, redis 7 | 1 / 51 | 0 | 6 / 624 | 1 / 13 | 848 (dockerd 157, containerd 58) |
| Tokyo | 7935 | 4170 | **872 (11%)** — node 824, traefik 27, pg 21+20sh | 3 / 146 | 2 / 17 | 11 / 2206 | — | 1036 (dockerd 113, containerd 39) |
| OCI | 11927 | 1718 | **807 (7%)** — node 774, traefik 26, pg 7+17sh | 2 / 87 | 1 / 3 | 2 / 43 | — | 857 (dockerd 109, containerd 39) |

`shared_buffers` = 128 MB (дефолт) у всех Postgres на всех серверах. Реально тронуто (shmem):
2–141 MB на инстанс.

## Выводы

1. **Control-plane Dokploy — стабильно 810–950 MB на любом боксе, и это почти целиком один
   Node-процесс (774–902 MB).** Traefik 26–58, dokploy-postgres 20–35, dokploy-redis 0–7. На
   Shchr это 22% RAM, на Bravo 16%, Tokyo 11%, OCI 7%, Habsida 4%.
2. **Реалистичная экономия от замены control-plane** (что угодно ≤50 MB вместо Node-процесса;
   общий Postgres остаётся): **≈ 760–900 MB на сервер** — Shchr −21%, Bravo −15%, Tokyo −11%,
   OCI −7%, Habsida −3.5%. Это единственный крупный, гарантированный выигрыш — и его даёт любой
   инструмент, который убирает Node-процесс, не обязательно boks.
3. **Консолидация app-Postgres в один инстанс почти не экономит RAM.** Реальная цена инстанса —
   10–180 MB, и это в основном тронутые `shared_buffers` (рабочий набор данных), а не overhead.
   Один общий инстанс с тем же рабочим набором займёт примерно ту же сумму; экономятся только
   дубли фоновых процессов (~20–30 MB × (N−1)) — на Habsida ~100 MB, на остальных ~30. Выигрыш
   консолидации — операционный (один бэкап/тюнинг/образ), не памятный. Ранняя оценка в
   architecture.md («12 × 100–150 MB») была ошибочной — она считала page cache.
4. **Redis на Habsida — это данные, а не overhead.** Из 1137 MB 1113 — один feed-кэш
   (`redis-calculate-digital-feed`). При переносе «всё в Postgres» эти байты не исчезнут, а
   переедут в unlogged-таблицу/page cache.
5. **dockerd — второй по величине системный потребитель:** 627 MB на Habsida (85 контейнеров/
   shim), 457 MB на Bravo при всего 16 контейнерах — аномально много, похоже на утечку или
   раздутые json-file логи, заслуживает отдельной проверки. Убирая per-app PG/Redis-контейнеры,
   снимаем ~10 MB на shim каждый; `--userland-proxy=false` добавит ещё немного.
6. Habsida — 24 GB, не «маленький сервер». Ужатые боксы (Shchr 4 GB, Bravo 6 GB) — именно там
   ~850 MB control-plane составляют 15–22% RAM, ради которых замена Dokploy имеет смысл.
