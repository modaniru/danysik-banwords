# Работа над сервисом banwords

- Писать backend на Go. Сервис использует стандартную библиотеку, runtime Node.js не требуется.
- Отвечать по-русски. Git commit/push/deploy выполнять только в разрешённом пользователем объёме.
- Единственный источник функциональных данных — `data/catalog.json` в Git. Менять этот файл обычным коммитом. История хранится в Git: не добавлять manifest, архив версий и lookup по идентификаторам.
- Каталог содержит только исходные слова, варианты замен, категории и явные matchMode/replaceMode. Общая закрытая схема отклоняет неизвестные поля. Клиентские локальные настройки в сервис не переносить.
- Свежесть всего каталога: SHA-256 стабильного JSON тела. GET /catalog отдаёт ровно эти байты и strong ETag; GET /catalog/hash отдаёт тот же hash. Отступы и порядок ключей файла не меняют hash; функциональные поля и порядок массивов меняют.
- Чтение /catalog и /catalog/hash допускается исключительно через проверенный service-токен: внутренний подписанный JWT должен содержать credential=service-token. Cookie-сессия, включая superadmin, данные не открывает. Спецификация /openapi.json может быть доступна по сессии с правом чтения.
- Входящий X-Auth-Token от клиента вырезает gateway (Traefik в Coolify; Caddy в прежней схеме). Сервис проверяет JWT/JWKS и не принимает внешний bw_ секрет напрямую. Не логировать заголовки, токены, тексты сообщений или слова каталога.
- Отдельную HTML-справку API не добавлять: спецификация выдаётся только JSON.
- При каждом изменении хендлеров, статусов или схем обновлять openapi.json и контрактные тесты в той же задаче.
- Перед передачей запускать make test (race detector и строгие 100% statements/исполняемых блоков), make check (go vet и gofmt) и make build. Не снижать покрытие ради успешного прогона.
- Тесты используют локальный HTTP и подменённые auth/JWKS. Не обращаться из тестов к production API или настоящему Twitch; отправка сообщений разрешается только отдельной явной просьбой.
- Идеи будущих изменений хранить в BACKLOG.md, не реализовывать без запроса.

## Связи и выкатка

- [Auth](../danysik-auth/AGENTS.md): `/verify`, JWKS, audience banwords, права
  `banwords:dictionaries:read` и credential=service-token. Контракт auth —
  `internal/httpapi/openapi.json`. Внешний bw_ secret проверяет auth, не banwords.
- [SayPatch](../../extensions/danysik-twitch-bw-checker/AGENTS.md) — потребитель
  `sp/1`, каталога, hash/ETag и режимов правил. При изменении формата сверять
  клиентские схемы/валидаторы; исходные данные здесь — `data/catalog.json`.
- [Frontend](../../danysik-frontend/AGENTS.md), `apps/banwords` — управление
  service-токенами через auth; это не отдельное хранилище каталога.
- [Infra](../../danysik-infra/AGENTS.md), [карта выкатки](../../danysik-infra/docs/service-map.md).
  Собственный `coolify.json` задаёт depends_on auth, BANWORDS_JWKS_URL, forward
  auth и probes. Не публиковать служебный порт/JWKS наружу.

Push master: проверки → GHCR → deploy-job Coolify. CI выбирает digest своей
сборки и ждёт deployment finished, API running:healthy и HTTPS probes.
Обычный релиз не требует SSH, браузера или общего launch. Не включать в коммит
незавершённые изменения других задач и не выкатывать соседей неявно.
Источник порядка действий — [доставка](../../danysik-infra/docs/delivery.md),
[переезд и восстановление](../../danysik-infra/docs/server-migration.md).
При первичном подключении/ротации: из workspace
`./danysik-infra/connect-service backend/danysik-banwords/coolify.json`.
Секреты не выводить; локальный API credential — ~/.config/coolify/api.token,
read+write+deploy без root/delete/read:sensitive. Откат версии — официальный
MCP list_rollback_images/rollback_application; volumes/env/SQL не откатывать.
Успешный image-job не доказывает деплой; проверять SHA/digest/deployment/probes.
