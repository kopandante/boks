# Plan: `trusted_proxies_ca` — Authenticated Origin Pulls Cloudflare (boks#134)

Base: 5777849 | Branch: feat/aop-origin-pull

Зачем: прокси верит адресу посетителя в заголовках от любого соединения с адресов Cloudflare; Worker с
чужого аккаунта CF подделывает `X-Forwarded-For` — уходит от бана или подставляет чужой адрес. До
перевода иностранного трафика dbauto на прокси CF (kopandante/todo#425) это нужно закрыть.

Не входит: включение AOP в зонах, смена образа прокси, apply на hb-sites — по слову владельца.

## Validation Commands
- `go build ./... && go vet ./... && go test ./...` в корне
- `cd proxy/gate && go vet ./... && go test ./...` (живой Caddy: `TestOriginPullThroughCaddy`)
- `cd proxy/ban && go test ./...`

## Acceptance Criteria
- AC1: `trusted_proxies_ca` в server.yml — PEM из одного или нескольких CERTIFICATE; ключ, мусор,
  пустое поле и поле без `trusted_proxies` — отказ; сертификат вне срока действия — отказ apply и
  rollback (status работает); в политике — DER.
- AC2: с CA сервер :443 получает `tls_connection_policies`: адреса `trusted_proxies` — `require_and_verify`
  по inline-пулу CA, остальные — пустая политика; `strict_sni_host: false`; доверие заголовкам на :443.
- AC3: живой Caddy: адрес прокси с сертификатом CA → приложение видит адрес из заголовка; без сертификата
  и с сертификатом чужого CA → соединение отказано; прямой посетитель (::1) → свой адрес, как раньше.
- AC4: с CA сервер :80 не доверяет никому, его бан не считает адреса `trusted_proxies`; бан :443 и
  политика не меняются.
- AC5: без CA конфиг прежний — ни `tls_connection_policies`, ни `strict_sni_host`.
- AC6: маркер 11 только с CA (и выше ключа); без CA — как раньше (todo#424). boks читает до 11.
- AC7: `boks server status`/apply печатают, от кого и как доверяется XFF.

## Pipeline
- [x] 0 worktree
- [x] 1 план
- [x] 2 реализация
- [x] 3 PR
- [x] 4 review-loop green
- [ ] 5 merge
