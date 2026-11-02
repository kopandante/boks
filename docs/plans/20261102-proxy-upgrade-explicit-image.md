# Plan: `proxy upgrade` без явного `proxy_image` отказывает (boks#178)

Base: 1dbe9cc | Branch: fix/proxy-upgrade-needs-explicit-image

Зачем: без ключа `proxy_image` `applyDefaults` подставляет встроенный образ (`DefaultProxyImage`, сейчас
ban9-gate4). `boks proxy upgrade` с таким конфигом молча заменил бы прокси всего узла на старый (на hb-sites
работает gate16). У почти всех сайтов hb-sites ключа нет (cars-pm, onestar-platform#189). Встроенное значение
не поднимаем: оно устаревает с каждым выпуском прокси. Версию прокси узла выбирают явно.

## Validation Commands
- `go build ./... && go vet ./... && go test ./...`
- `go test ./internal/config -run TestProxyImageNamed` — признак «задан явно»: нет ключа / `proxy_image:` без значения / `""` — не задан
- `go test ./cmd/boks -run TestProxyUpgradeWithoutProxyImage` — отказ до подключения к серверу, `--force` отказ не снимает
- мутация: убрать вызов `cfg.RequireProxyImage()` из `proxyCmd` → тест краснеет; `ProxyImageNamed = true` всегда → тест config краснеет

## Acceptance Criteria
- AC1: `boks proxy upgrade` с конфигом без `proxy_image` завершается ошибкой до любого подключения; прокси на узле не тронут.
- AC2: с `proxy_image` поведение прежнее (включая отказ брать более старый образ без `--force`).
- AC3: `ProxyImage` по-прежнему заполняется встроенным значением для `boot`, `migrate` и выката (они не заменяют работающий прокси).
- AC4: `DefaultProxyImage` не меняется.

## Вне объёма
- `proxy boot`/`migrate` и подъём прокси при выкате берут встроенный образ, если ключа нет — на узле без прокси; отдельный вопрос.
- Предупреждение выката «the config names the older …» при отсутствии ключа говорит «config names», хотя это встроенное значение — текст не трогаем.
- Единое место версии прокси в политике узла (hb-sites.yml) — отдельное решение владельца.

## Pipeline
- [x] 1 страж `Config.RequireProxyImage` + признак `ProxyImageNamed`
- [x] 2 вызов в `proxyCmd` (upgrade), справка
- [x] 3 тесты + мутации
- [ ] 4 PR через /review-loop, merge
- [ ] 5 установка на hb-sites — только по слову владельца через infra-pm
