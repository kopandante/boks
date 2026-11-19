# Plan: исключения у сигнатуры гейта (`unless`) — Opera Mobile и Samsung Internet не бан (todo#419)

Base: 6e0fa5d | Branch: feat/gate-signature-unless

Зачем: сигнатура `chrome-no-zstd` (enforce, dbauto, ревизия 48) банит на 24 ч живых посетителей: 19.11 в 22:54Z
Opera Mobile 104 (Jazztel, ES, 35 успешных запросов до бана). По журналу за 14 дней Opera Mobile (2877 из 2898
запросов) и Samsung Internet (360 из 362) не шлют zstd — допущение «Chrome ≥ 124 всегда шлёт zstd» неверно для
них. Слово владельца 19.11 «Ок, давай чинить Opera Mobile» (окно infra-pm …b7bace69….jsonl:412), вариант (в):
исключение по бренду Sec-CH-UA, сигнатура для остальных остаётся enforce. Вариант (б) (в log) не делается.

## Что меняется
- `proxy/gate/signature.go`: поле `Unless []HeaderPattern` — запрос, у которого хоть один названный заголовок
  подходит под шаблон, сигнатуре не принадлежит; шаблон, принимающий пустую строку, отказывает при Validate.
- `docs/architecture.md`: раздел сигнатур.
- Политика (отдельный PR в backends после образа gate18): `unless: [{name: sec-ch-ua, pattern: '"(OperaMobile|Samsung (Internet|Browser))"'}]`
  у `chrome-no-zstd`, ревизия 100.

## Validation Commands
- `cd proxy/gate && go vet ./... && go test . -run Signature -count=1` (точечно; полный прогон — на boat)
- `cd proxy/gate && go test ./... -count=1` на boat
- прогон по журналу: `~/.cache/infra-dbauto/replay-no-zstd.py 336 6 cars.dbauto.kr`

## Acceptance Criteria
- AC1: Opera Mobile (104, 103 при другом порядке брендов) и Samsung Internet (28, 30) и Samsung Browser 31 не матчатся.
- AC2: образцы ботов (Windows Chrome 145/146 с AWS-адресов, Chrome 125 без Accept-Language) матчатся по-прежнему; Brave и десктопная Opera без zstd не исключены.
- AC3: исключение задано только по Sec-CH-UA: «OPR/…» или «SamsungBrowser/…» в User-Agent без Sec-CH-UA не щадит.
- AC4: исключённый запрос бана не получает; другая сигнатура, совпавшая с тем же запросом, берёт его как раньше.
- AC5: шаблон `unless`, принимающий пустую строку, отказывает; шаблон, не компилирующийся, отказывает при Provision.
- AC6: мутация (убрать проверку исключения) валит `TestSignatureUnless*`.
- AC7: прогон по журналу за 14 дней на cars.dbauto.kr: 9 адресов под старую форму; 4 перестают матчиться
  (Opera Mobile 188.77.90.128, 146.185.89.130; Samsung Internet 51.75.171.61, 105.235.138.29), 5 остаются
  (3.208.10.80, 54.234.25.230, 172.178.68.104 — боты AWS/Azure; 79.137.151.71 — Chrome 125 без языка; 46.205.192.62 — Brave).

## Pipeline
- [x] 1 поле `Unless`, Provision/Validate, matches
- [x] 2 тесты по реальным заголовкам журнала, мутация
- [x] 3 прогон по журналу за 14 дней
- [x] 4 docs/architecture.md
- [ ] 5 PR через /review-loop до сертификата
- [ ] 6 строка infra-pm: номер PR и итог прогона — до выката
- [ ] 7 merge, `proxy/TAG` → gate18, пины, политика ревизия 100, выкат (по слову infra-pm)
