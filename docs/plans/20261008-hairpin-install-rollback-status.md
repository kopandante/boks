# Hairpin: install, rollback, status (2026-10-08)

Продолжение `docs/plans/20261008-hairpin.md` (PR #92, merge `4cbdab4`). В #92 правило firewall для
hairpin ставит только `server apply`, а проверку из контейнера делает только `boks deploy`.

## Решение владельца

1. `boks server install` ставит правило так же, как `server apply`: свежий сервер готов к hairpin сразу.
2. `boks rollback` приложения с `tls: true` после отката запускает ту же проверку, что deploy, с той же
   громкой ошибкой.
3. `boks server status` показывает строку о правиле на каждом сервере: есть, нет, есть цепочка без него;
   без правила — подсказка `server apply`. Ручной `nft -f` между деплоями видно сразу.

Не делаем: `table ip filter`/`INPUT`, описанные в синтаксисе nft, по-прежнему только предупреждение.

## Работы

- [x] `ensureHairpin` — шаг `EnsureHairpin` без своего замка; `Install` зовёт его после `proxy.Boot` под
      своим замком допуска, по соединению запуска (root/sudo), сбой — `fail` (журнал `failed`,
      если установка открыла запись)
- [x] `CheckRolledBackHairpin`: хосты восстановленного релиза (`current` → snapshot → `restored`); в
      `dispatch` rollback после отката на всех серверах — `everyServer(... "hairpin" ...)`, как deploy
- [x] `HairpinStatus`: факты `readHairpin`, затем одна проверка `hairpinIn` на цепочку (та же, что в
      скрипте); строки «есть / нет + `boks server apply` / нет держателя / юнит выключен», предупреждения
      apply; `server status` печатает их на каждом сервере
- [x] тесты по образцу #92 и мутации (16 мутантов, все убиты)
- [x] `docs/architecture.md`, usage
- [x] живая проверка на OrbStack Debian 13 (Docker 26.1.5 из docker.io, nftables 1.1.3), `inet filter
      input` с `policy drop`, 80/443 только с `eth0`, с `br-*` только `10.88.0.0/24` (как hb без
      временного правила), приложение `traefik/whoami` с `tls: true` на `app.<ip>.nip.io`:
  - свежая VM: `server status` до install — `! … without boks's hairpin rule … boks server apply`;
    `server install` — `inserted into inet filter input`, `server ready for boks`; сразу `deploy` —
    hairpin отвечает, без отдельного apply; повтор install — правило не дублируется, `nothing to change`;
  - `server status` после install — `hairpin rule in inet filter input, kept by nftables.service`;
    перезагрузка VM — то же, deploy проходит;
  - ручной `nft -f /etc/nftables.conf` — status `! … without boks's hairpin rule`, `boks rollback`
    откатывает и падает с кодом 1: `Connecting to … (…:443) wget: download timed out` и подсказкой
    `boks server apply`; после apply status снова `kept`, rollback проходит;
  - удалённый drop-in + `daemon-reload` — status `! … nftables.service would not put it back`, apply
    возвращает; `systemctl disable nftables` — status `nftables.service is not enabled`
- [ ] VM `boks-hp2` удалить после merge

## Проверка

```
go vet ./... && go test ./...
```
