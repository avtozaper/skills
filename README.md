# Скиллы 1888.center

Маркетплейс скиллов (agent skills) для Claude Code с сайта [1888.center](https://1888.center) — курсы «Современное SEO-продвижение».

## Установка

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

## Скиллы

| Скилл | Что делает | Описание |
|---|---|---|
| `aio-content-writing` | Тексты под цитируемость в AI-поисковиках: Answer Unit, чанки 300–500 символов, Query Fanout, Information Gain | [страница](https://1888.center/courses/skills/aio-content-writing/) |

## Структура репозитория

```
.claude-plugin/marketplace.json   каталог для git-канала
plugins/<name>/
├── .claude-plugin/plugin.json    манифест плагина (единственный источник версии)
└── SKILL.md                      сам скилл
```

Один скилл = один плагин. `SKILL.md` лежит в корне плагина, папки `skills/` нет — Claude Code грузит такой плагин как single-skill.

## Разработка

Чтобы править скилл и сразу видеть результат локально, замените личную копию симлинком:

```bash
rm -rf ~/.claude/skills/aio-content-writing
ln -s ~/skills/plugins/aio-content-writing ~/.claude/skills/aio-content-writing
```

Установленный плагин с тем же именем перебивает эту копию: Claude Code сообщит `Not loaded — the name is already taken`, и вы будете править файл, который не подгружается. Пока правите скилл — держите его удалённым (`claude plugin uninstall <name>`), а установленную версию ставьте только чтобы проверить, что получат пользователи.

Перед публикацией:

```bash
claude plugin validate ./plugins/aio-content-writing --strict
```

Версия правится **только** в `plugins/<name>/.claude-plugin/plugin.json`; в `marketplace.json` она обязана совпадать — это проверяет сборщик `scripts/build-skills.sh` в репозитории сайта. Без бампа версии установленные копии не обновятся.

## Лицензия

MIT
