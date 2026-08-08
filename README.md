# Скиллы 1888.center

Скиллы (agent skills) с сайта [1888.center](https://1888.center) — курсы «Современное SEO-продвижение». Формат стандартный: `SKILL.md` с YAML-фронтматтером, поэтому скиллы работают не только в Claude Code, но и в Manus, Cursor, Codex и других агентах, которые понимают Agent Skills.

## Установка в Claude Code

Основной канал — свой хостинг. Не нужен ни git, ни GitHub-аккаунт, ни SSH-ключи:

```bash
claude plugin marketplace add https://1888.center/marketplace.json
claude plugin install aio-content-writing@1888-center
```

Запасной канал — этот репозиторий (нужен установленный git):

```bash
claude plugin marketplace add https://github.com/avtozaper/skills.git
claude plugin install aio-content-writing@1888-center
```

Оба канала зарегистрированы под одним именем маркетплейса `1888-center`, поэтому команда установки одинаковая. Для канала с zip-архивами нужен Claude Code **2.1.224 или новее** (`claude update`).

Обновление и удаление:

```bash
claude plugin update aio-content-writing
claude plugin uninstall aio-content-writing
```

## Установка в другие агенты

**Cursor, Codex, Copilot, Windsurf, Gemini, Cline и другие** — через CLI открытой экосистемы скиллов, он сам разложит файлы по нужным папкам обнаруженных агентов:

```bash
npx skills add avtozaper/skills --skill aio-content-writing -g
```

**Manus** — Skills в левой панели → **+ Add**. Либо «Upload a skill» с zip-архивом ([скачать](https://1888.center/skills/aio-content-writing.zip)), либо импорт из GitHub по ссылке на этот репозиторий. Вызов в чате — `/aio-content-writing`.

**Любой другой агент** — положите папку скилла туда, где агент ищет инструкции, или просто скормите ему `SKILL.md` целиком. Внутри чистый markdown без скриптов и внешних зависимостей.

## Скиллы

| Скилл | Что делает | Описание |
|---|---|---|
| `aio-content-writing` | Тексты под цитируемость в AI-поисковиках: Answer Unit, чанки 300–500 символов, Query Fanout, Information Gain | [страница](https://1888.center/courses/skills/aio-content-writing/) |

## Структура репозитория

```
.claude-plugin/marketplace.json   каталог для git-канала Claude Code
skills/<name>/
├── .claude-plugin/plugin.json    манифест плагина (единственный источник версии)
└── SKILL.md                      сам скилл
```

Раскладка `skills/<name>/SKILL.md` выбрана намеренно: это стандартное место, где скилл ищут `npx skills` и импорт из GitHub в других агентах. Для Claude Code та же папка одновременно является корнем плагина — `SKILL.md` лежит в корне, папки `skills/` внутри нет, поэтому плагин грузится как single-skill. Один скилл = один плагин.

## Разработка

Чтобы править скилл и сразу видеть результат локально, замените личную копию симлинком:

```bash
rm -rf ~/.claude/skills/aio-content-writing
ln -s ~/skills/skills/aio-content-writing ~/.claude/skills/aio-content-writing
```

Установленный плагин с тем же именем перебивает эту копию: Claude Code сообщит `Not loaded — the name is already taken`, и вы будете править файл, который не подгружается. Пока правите скилл — держите его удалённым (`claude plugin uninstall <name>`), а установленную версию ставьте только чтобы проверить, что получат пользователи.

Перед публикацией:

```bash
claude plugin validate ./skills/aio-content-writing --strict
```

Версия правится **только** в `skills/<name>/.claude-plugin/plugin.json`; в `marketplace.json` она обязана совпадать — это проверяет сборщик `scripts/build-skills.sh` в репозитории сайта. Без бампа версии установленные копии не обновятся.

## Лицензия

MIT
