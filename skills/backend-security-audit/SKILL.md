---
name: backend-security-audit
description: Аудит безопасности бэкенда и сайта — проверка кода и живого сервера на дыры по OWASP Top 10:2025 и OWASP API Top 10:2023. SQL- и прочие инъекции (команды ОС, NoSQL, шаблоны SSTI, CRLF), IDOR/BOLA (чужая запись по номеру в адресе), массовое присвоение (role=admin в форме), небезопасная десериализация, утечка данных, слабый вход, XSS, подмена текста через адрес, CSRF, открытые редиректы, SSRF, обход путей и загрузка файлов, XXE, JWT и криптография, гонки и бизнес-логика, DoS и лимиты, вебхуки и чужие API, CORS и Host-заголовок, цепочка поставок (зависимости, CDN, GitHub Actions), обработка ошибок, журнал, настройка сервера, LLM и prompt injection, WordPress и Bitrix. Используй, когда пользователь просит «проверь на уязвимости», «аудит безопасности», «безопасный ли бэкенд», «проверь код на дыры», «напиши тесты безопасности», присылает видео или чек-лист про взломы и просит сверить с проектом, или перед выкладкой новой админки, кабинета, API или бота. Подходит для Python (FastAPI, Django, Flask), PHP (WordPress, Bitrix, Laravel, чистый PHP) и Node.
---

# Аудит безопасности бэкенда

Общая причина почти всех дыр одна: **сервер поверил тому, чему верить было нельзя** — вводу пользователя, номеру из адреса, полям формы, присланным байтам, тексту в ссылке, ответу чужого API, URL для скачивания, имени файла. Ищем каждое место, где внешние данные влияют на запрос к базе, права, путь к файлу, сетевой запрос, разметку страницы или выполняемый код.

Ориентиры: OWASP Top 10:2025 (A01 Broken Access Control, в т. ч. SSRF · A02 Security Misconfiguration · A03 Software Supply Chain Failures · A04 Cryptographic Failures · A05 Injection · A06 Insecure Design · A07 Authentication Failures · A08 Software or Data Integrity Failures · A09 Logging & Alerting Failures · A10 Mishandling of Exceptional Conditions) и OWASP API Security Top 10:2023 (BOLA, Broken Authentication, Broken Object Property Level Authorization, Unrestricted Resource Consumption, BFLA, Unrestricted Access to Sensitive Business Flows, SSRF, Misconfiguration, Improper Inventory, Unsafe Consumption of APIs). Для глубокой проверки — OWASP ASVS 5.0 и WSTG.

## Порядок работы

1. **Карта входов.** Найди все маршруты (routes, контроллеры, `*.php` в веб-корне, ajax-обработчики, вебхуки, cron-скрипты, доступные по HTTP, CLI-команды) и раздели на публичные и требующие входа, по ролям. Для каждого: что принимает (адрес, форма, JSON, файлы, заголовки, cookie), что делает (читает/пишет БД, файлы, ходит в сеть, шлёт письма/SMS, тратит деньги).
2. **Пройди разделы 1–25** — поиском по коду (подсказки в каждом), затем чтением найденного. Grep только находит кандидатов; вывод — после чтения кода вокруг. Разделы, неприменимые к проекту (нет загрузки файлов, нет JWT), отметь «нет в проекте».
3. **Автоматические сканеры** (раздел «Инструменты») — как дополнение, не замена чтению.
4. **Живой сервер — только безопасные одиночные запросы** (раздел «Живые проверки»): заголовки, отражение параметров, открытые служебные пути, счёт секретов в логах без вывода значений.
5. **Отчёт** (формат в конце). Ничего не правь и не выкладывай без просьбы.
6. **После исправлений — регрессионные тесты**, воспроизводящие атаку (шаблоны в разделе «Тесты»).

---

## 1. SQL-инъекция (A05)

Ввод вклеен в текст запроса, а не передан параметром. Кавычка закрывает строку, `' OR 1=1 --` отдаёт все строки; `UNION SELECT` читает другие таблицы; слепая — по задержке `SLEEP(5)`.

- Python: `f"SELECT … {x}"`, `"…" + x`, `.format(` и `%` в SQL, `text(f"…")` в SQLAlchemy, `.extra()`/`.raw()` в Django с подстановкой. Норма — `?`/`%s`/`:name` с отдельными аргументами.
- PHP: `"SELECT … $var"`, `'…' . $_GET[…]`, `mysqli_query($c, "…$x")`, `intval` забыт у id. Норма — `prepare` + `bind_param`/`execute([...])`, в WordPress `$wpdb->prepare`, в Bitrix — ORM/`$DB->ForSql()`.
- Node: шаблонные строки `` `SELECT … ${x}` ``, `sequelize.query` с подстановкой, `knex.raw` с конкатенацией.
- **Имена таблиц, колонок, `ORDER BY`, `LIMIT`, направление сортировки** параметром не передаются — допустимы только из белого списка в коде. Проверь, откуда берётся каждое такое имя.
- `LIKE` с вводом: экранировать `%` и `_`, иначе поиск «%» выгружает всё (утечка, нагрузка).
- Поиск: `grep -rnE 'f"(SELECT|UPDATE|INSERT|DELETE)|(SELECT|WHERE|ORDER BY).*(\$_(GET|POST|REQUEST)|\+ *req\.)' .`

## 2. Другие инъекции (A05)

- **Команды ОС:** `subprocess(..., shell=True)`, `os.system`, `os.popen`, PHP `exec/shell_exec/system/passthru/proc_open/` и обратные кавычки, Node `child_process.exec`. Норма — список аргументов без shell (`subprocess.run([...])`, `execFile`), `escapeshellarg` в PHP, и `--` перед пользовательскими аргументами (против `-oProxyCommand=…`, `--upload-pack=…` в ssh/git/curl/tar).
- **NoSQL:** MongoDB `{"password": {"$ne": null}}` из JSON-тела проходит вход; запрещать объекты там, где ждём строку; `$where`, `$function` с вводом.
- **Шаблоны (SSTI):** ввод пользователя становится шаблоном: `render_template_string(user)`, `Template(user).render()`, `Environment().from_string`, Twig/Blade/Smarty из строки БД, которую правит пользователь. `{{7*7}}` → `49` = дыра, ведёт к выполнению кода.
- **CRLF и заголовки:** ввод в `Location`, `Set-Cookie`, любой заголовок ответа, `header()` в PHP — перевод строки внедряет заголовки. То же в письмах: ввод в `To/Subject/From` без очистки `\r\n` — рассылка спама через форму.
- **LDAP, XPath** — экранирование по их правилам.
- **Журналы (log injection):** перевод строки в логин подделывает записи журнала; при просмотре журнала в браузере — XSS.
- **CSV/формулы в экспорте:** значение, начинающееся с `= + - @`, выполняется в Excel. Экспорт — с префиксом `'` для таких ячеек.
- **Регулярки из ввода:** `re.compile(user)` — ReDoS и обход; экранировать `re.escape`.

## 3. IDOR / BOLA — чужая запись по номеру (A01, API1)

`/order/101` → `/order/102` открывает чужой заказ: сервер проверил «вошёл ли», но не «чьё это».

- Для каждого маршрута с id в адресе, теле, заголовке или имени файла (просмотр, правка, удаление, скачивание, экспорт, показ секрета, отметка «оплачено», запуск действия, восстановление версии) найди проверку прав **на конкретную запись** после её загрузки.
- Особое внимание: удаление сессий/устройств/подписок по id или токену, файлы по имени, ajax-эндпоинты, «вспомогательные» API для фронта, мобильное API, старые версии API (`/v1/` без проверок при наличии `/v2/` — API9 Improper Inventory).
- Ссылки на другие записи в формах (`server_id`, `owner_id`, `team_id`) — тоже вход: нельзя привязать запись к чужому объекту.
- Последовательные числовые id упрощают перебор, но **не являются** причиной: UUID не заменяет проверку прав.
- **BFLA (API5):** функции другой роли — обычный пользователь вызывает `/admin/...` или `DELETE` напрямую, потому что кнопку скрыли, а маршрут не проверяет роль. Проверь проверку роли на каждом админском маршруте, а не в шаблоне.
- **Ошибка в проверке прав = отказ** (fail closed): исключение, `None`, пустой список прав не должны давать доступ.

## 4. Массовое присвоение (A01, API3)

Сервер копирует в запись всё, что пришло, — атакующий дописывает `role=admin`, `is_admin=1`, `balance`, `user_id`, `created_by`, `verified=true`, `price`.

- Ищи `**request.json`, `Model(**data)`, `.update(data)`, `serializer` с `fields="__all__"`, `$model->fill($request->all())` при пустом `$fillable`/`$guarded = []`, `foreach ($_POST as $k => $v) … SET $k`, `Object.assign(user, req.body)`, `{...req.body}`.
- Норма — явный список разрешённых полей для каждой роли; роль, владелец, баланс, статус оплаты меняются только отдельным маршрутом с проверкой прав, роль — по белому списку.
- Обратная сторона (API3): ответ отдаёт поля, которые этой роли видеть нельзя (см. раздел 6).

## 5. Небезопасная десериализация и целостность (A08)

- Python: `pickle.load(s)`, `yaml.load` без `SafeLoader`, `marshal`, `shelve`, `jsonpickle`, `torch.load` без `weights_only=True`, `joblib.load` чужих файлов, `eval(`/`exec(`.
- PHP: `unserialize()` данных из cookie, запроса или из БД, куда пишет пользователь (POP-цепочки); `phar://` в файловых функциях; `eval`, `assert` со строкой, `preg_replace` с `/e`, `create_function`, `extract($_REQUEST)`.
- Node: `node-serialize`, `eval`, `new Function`, `vm` с внешним вводом; **prototype pollution** — рекурсивный merge/`lodash.merge`/`_.set` с ключами `__proto__`, `constructor`, `prototype` из JSON; лечится фильтром ключей, `Object.create(null)`, `Map`.
- Подписанные данные на клиенте (cookie-сессии Flask/Rails, состояния) — секрет подписи сильный и не в репозитории.
- Обновления, плагины, импорты конфигов — проверка подписи/хэша источника.
- Норма — JSON + проверка схемы (pydantic, zod, JSON Schema).

## 6. Утечка данных (A01, A04, API3)

API отдаёт всю строку пользователя с хэшем пароля и токеном; секреты в логах.

- Ищи ответы, сериализующие строки БД целиком: `JSONResponse(dict(row))`, `return user`, `json_encode($row)`, `res.json(user)`, `SELECT *` → ответ, `model_dump()` без `exclude`.
- Хранение: пароли — только медленный хэш (argon2id/bcrypt/scrypt; md5/sha1/sha256 без соли — дыра); токены сессий, одноразовые коды, ключи восстановления — в БД хэшем; секреты (ключи API, пароли доступов) — зашифрованы, ключ вне БД и вне веб-корня, показ — отдельным запросом с правами и журналом.
- Логи: `log.*(… token|password|secret|key …)`, `print(request.body)`, `error_log(print_r($_POST))`, логирование заголовков `Authorization`/`Cookie`, URL с токенами в access-логах (токены в адресе попадают в логи прокси, историю браузера, `Referer`).
- Формы правки не подставляют сохранённые пароли в `value=`.
- Сообщения об ошибках не раскрывают, существует ли логин/почта (форма входа, восстановления, регистрации).
- Публичные файлы: дампы `.sql`, `.env`, `.git/`, `*.zip`/`*.tar.gz`, `phpinfo.php`, `backup/`, `*.bak`, `*.old`, `~`-копии, `composer.json`/`package.json` с версиями, `.DS_Store`, source maps `*.js.map` на проде.
- Кэш: личные страницы с `Cache-Control: private, no-store`, иначе CDN отдаст их другому (web cache deception: `/account/x.css`).

## 7. Слабый вход и сессии (A07, API2)

Проверь по пунктам:
- лимит попыток по IP **и** по логину **и** общий; задержка; одинаковое время и текст для несуществующего логина;
- второй фактор (TOTP, код в мессенджер/почту, WebAuthn) — и нельзя ли обойти его прямым заходом на следующий шаг, повторить код, перебрать 6 цифр (лимит попыток кода и срок жизни);
- коды и токены сброса: случайные ≥128 бит, хэшем в БД, короткий срок, одноразовые, гаснут после смены пароля; ссылка сброса строится из настроек, **не из `Host`** (иначе password reset poisoning — письмо со ссылкой на домен атакующего);
- сессии: токен из `secrets`/`random_bytes`, cookie `HttpOnly; Secure; SameSite`, без широкого `Domain=`; новая сессия после входа (против фиксации); истечение по простою и абсолютное; отзыв всех сессий при смене пароля, отключении пользователя, смене роли; выход действительно удаляет сессию на сервере;
- пароли: минимум 12 символов, проверка по утёкшим (HIBP k-anonymity) по желанию, без максимальной длины ниже 64, без принудительной смены по расписанию;
- **реальный IP за прокси/Cloudflare**: если приложение видит только `127.0.0.1`, лимит «по IP» становится общим, а журнал без адресов. И наоборот — если `X-Forwarded-For` принимается от кого угодно, IP подделывается. Норма — доверять заголовку только от своего прокси (uvicorn `forwarded_allow_ips`, Caddy `trusted_proxies` + `CF-Connecting-IP`, nginx `set_real_ip_from` + `real_ip_header`);
- регистрация открыта? Если нет — маршрут действительно закрыт, а не только скрыт;
- приглашения и OAuth: `state` проверяется, `redirect_uri` — точное совпадение, не префикс.

## 8. XSS (A05)

Текст пользователя вставлен в HTML как есть — браузер выполнит `<script>`.

- Шаблоны: `|safe`, `Markup(`, `{% autoescape false %}`, `{!! !!}` (Blade), `<?= $x ?>` без `htmlspecialchars($x, ENT_QUOTES)`, `dangerouslySetInnerHTML`, `v-html`.
- Контексты: внутри атрибута без кавычек, в `href` (`javascript:`-ссылки — проверять схему), в `<script>` (JSON — через `json.dumps` + замена `</`), в `style`, в обработчиках `on*`.
- JS: `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `$(…).html()`, `eval`, `setTimeout(строка)` с внешними данными; `location.hash`/`postMessage` без проверки `origin` (DOM XSS). Норма — `textContent`.
- Внешние данные — это и результаты проверок, ответы чужих API, сообщения коммитов, имена файлов, параметры вебхуков, EXIF, заголовки писем. Если они уходят в Telegram с `parse_mode=HTML` или в письмо — тоже экранировать.
- SVG и HTML, загруженные пользователем и отданные с того же домена, — хранимый XSS (раздел 11).
- Markdown: рендерер с отключённым сырым HTML или с санитайзером.
- Если HTML разрешён — санитайзер (nh3/bleach, sanitize-html, DOMPurify, HTML Purifier).
- Защитный слой: `Content-Security-Policy` без `unsafe-inline`/`unsafe-eval`, с `object-src 'none'; base-uri 'none'; frame-ancestors 'none'`.

## 9. Подмена текста через адрес (content injection)

Сообщение об ошибке или «успешно» берётся из параметра адреса (`?e=…`, `?msg=…`, `?m=…`, `?error=`) и выводится на странице. Скрипт не пройдёт (экранирование), но злоумышленник шлёт ссылку на **ваш** домен с текстом «Ваш аккаунт заблокирован, позвоните по номеру…». Опаснее всего на страницах входа и приглашений.

- Проверка: открыть страницу с `?e=TEST123` / `?m=TEST123` / `?message=TEST123` и найти TEST123 в ответе.
- Норма: код ошибки из белого списка, флеш-сообщение в сессии, либо текст в адресе + HMAC-подпись сервера (показывать только при верной подписи). Сообщения, которые формирует JS после действия, — через `sessionStorage`, не через адрес.

## 10. CSRF, открытые редиректы, кликджекинг (A01)

- Каждый изменяющий запрос из браузера (POST/PUT/PATCH/DELETE) — с CSRF-токеном, сравнение в постоянное время (`hmac.compare_digest`, `hash_equals`). Изменения через GET недопустимы (картинка `<img src="/delete/5">`). Вход и выход — тоже под CSRF (login CSRF). `SameSite` — дополнительный слой, не единственный. JSON-API: проверять `Content-Type: application/json` или заголовок с токеном.
- Параметры `back=`, `next=`, `redirect=`, `return_url=`, `url=` — только свои пути: начинается с `/`, не `//`, нет `\`, нет `/\`, нет схемы; или белый список доменов с точным сравнением хоста после разбора URL.
- Кликджекинг: `X-Frame-Options: DENY` или CSP `frame-ancestors 'none'` на всех страницах с действиями.

## 11. Файлы: обход путей, загрузка, архивы, XML (A01, A05)

- **Обход путей:** имя/путь из запроса в `open()`, `send_file`, `FileResponse`, `include`/`require`, `file_get_contents`, `readfile`, `fs.readFile`, `path.join(base, user)`. Атаки `../`, `..%2f`, `%2e%2e/`, `....//`, абсолютный путь, нулевой байт, симлинки. Норма — id → путь из БД, или `resolve()` + проверка, что результат внутри базовой папки. PHP: `include $_GET['page']` — локальное/удалённое включение файлов.
- **Загрузка файлов:** проверка расширения по белому списку **и** содержимого (magic bytes), новое случайное имя, хранение вне веб-корня или в папке, где сервер не исполняет скрипты (`.php`, `.phtml`, `.phar`, `.htaccess` в uploads!), лимит размера, `Content-Disposition: attachment` и `X-Content-Type-Options: nosniff` при отдаче, SVG/HTML — только как вложение или с отдельного домена. Картинки — пересохранять (снимает EXIF с геолокацией и полиглоты); ImageMagick/Ghostscript — политика с запретом опасных кодеков; лимит пикселей против «бомбы разрешения».
- **Архивы:** zip slip — имена внутри архива с `../` при распаковке; zip-бомба — лимит распакованного размера и числа файлов.
- **XXE:** разбор XML с внешними сущностями (`lxml` с `resolve_entities=True`, `xml.etree` старых версий, PHP `libxml` без `LIBXML_NONET`, Java по умолчанию) читает локальные файлы и делает SSRF. Норма — `defusedxml`, отключённые DTD. Касается и SVG, DOCX/XLSX, RSS, SAML.

## 12. SSRF — сервер сам ходит по URL от пользователя (A01, API7)

Импорт по ссылке, превью ссылок, вебхуки «куда слать», загрузка аватара по URL, проверки мониторинга, PDF/скриншот-генераторы, прокси картинок.

- Опасные цели: `127.0.0.1`, `localhost`, `0.0.0.0`, `[::1]`, `169.254.169.254` (метаданные облака — ключи!), `10/8`, `172.16/12`, `192.168/16`, `100.64/10`, внутренние имена, порты Redis/MySQL/Docker API; схемы `file://`, `gopher://`, `dict://`, `ftp://`.
- Обходы: десятичный/восьмеричный IP (`2130706433`, `0177.0.0.1`), IPv6-обёртки (`::ffff:127.0.0.1`), DNS, указывающий на внутренний адрес, DNS rebinding (проверили один IP — подключились к другому), редирект с внешнего адреса на внутренний, `user@host`-трюки в URL.
- Норма: только `http/https`; разрешить имя → проверить **все** IP → подключаться именно к проверенному IP; редиректы выключить или проверять каждый шаг; таймаут и лимит размера ответа; не показывать пользователю тело ответа/ошибки соединения (иначе сканер внутренней сети); исходящий файрвол; IMDSv2 в AWS.
- Если SSRF — осознанная функция для доверенных ролей (мониторинг, админ-импорт): зафиксировать, кто может задавать URL, и что внутренние адреса всё равно заблокированы или сознательно разрешены.

## 13. Криптография, токены, JWT (A04)

- Случайность для секретов — только `secrets`/`os.urandom`, `random_bytes`/`random_int`, `crypto.randomBytes`. `random`, `mt_rand`, `rand`, `uniqid`, `Math.random`, время — предсказуемы.
- Сравнение секретов/подписей/токенов — в постоянное время.
- Шифрование: AEAD (AES-GCM, ChaCha20-Poly1305), уникальный nonce; не ECB, не самодельные схемы, не base64 «вместо шифрования»; привязка к контексту (associated data) против перестановки шифротекстов между записями.
- TLS наружу: нет `verify=False`, `CURLOPT_SSL_VERIFYPEER => false`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0`.
- **JWT:** алгоритм фиксирован на сервере (не из заголовка токена) — атаки `alg: none` и подмена RS256→HS256 с публичным ключом как секретом; сильный секрет (перебор слабых HS256 — hashcat); обязательные `exp`, `aud`, `iss`; `kid`/`jku`/`x5u` из токена не ведут на чужие ключи и файлы; отзыв (короткий срок + refresh с ротацией); JWT не в `localStorage`, если есть XSS-риск.
- Секреты не в коде и не в репозитории — в т. ч. в истории git (`gitleaks detect`, `trufflehog git file://.`). Найденный в истории секрет — ротировать, удаления из истории мало.
- Ключи API с минимальными правами и сроком; разные ключи для разработки и прода.

## 14. Бизнес-логика и гонки (A06, API6)

- **Гонки (TOCTOU, limit overrun):** проверка «хватает ли баланса/использован ли код/не превышен ли лимит» и запись — отдельными шагами. 20 параллельных запросов списывают промокод 20 раз, отправляют 20 выплат, открывают 20 окон. Норма — атомарный `UPDATE … WHERE balance >= ?` с проверкой числа строк, уникальный индекс, транзакция с блокировкой, идемпотентные ключи.
- Цена, скидка, количество, валюта приходят с клиента; отрицательные и дробные количества; переполнение; пропуск шагов процесса (оплата → сразу «готово»); повтор вебхука оплаты; смена тарифа без оплаты.
- **Чувствительные процессы без ограничений (API6):** массовая регистрация, массовая отправка кодов/писем/SMS (деньги и бан отправителя), выкуп слотов, накрутка голосов — лимиты на пользователя/IP/номер, капча, подтверждение.
- Одноразовые коды и ссылки действительно одноразовые; смена почты/телефона подтверждается старым и новым каналом.

## 15. Ресурсы и отказ в обслуживании (API4)

- Лимит размера тела запроса и загружаемых файлов; лимит числа элементов в массивах JSON; `per_page` с потолком; поиск без ограничения длины строки.
- Таймауты всех исходящих запросов (HTTP, SSH, БД); пул соединений; фоновые задачи с ограничением параллельности и защитой от повторного запуска.
- Rate limit на дорогих и платных эндпоинтах: отправка кодов, писем, вызовы LLM, генерация PDF/картинок, экспорт, «проверить всё».
- ReDoS: регулярки с вложенными квантификаторами `(a+)+`, `(.*)*` на пользовательском вводе.
- Хэширование паролей огромной длины (лимит 1–4 КБ на поле пароля), распаковка архивов, разбор картинок, GraphQL — глубина и сложность запроса, батчинг алиасов.
- Собственная платформа не должна стать источником DoS для чужих серверов (параллельные проверки одного IP, повторы без паузы → бан IP у хостера).

## 16. Вебхуки и чужие API (A08, API10)

- **Входящие вебхуки** (платёжки, CRM, мессенджеры, GitHub): проверка подписи HMAC над сырым телом в постоянное время, метка времени и окно (против повтора), идемпотентность по id события; секрет в URL — только если других вариантов нет, и тогда длинный и не в логах.
- **Ответы чужих API** — такие же недоверенные данные: валидация схемы, экранирование перед выводом, лимиты размера, таймауты, не следовать редиректам вслепую, TLS с проверкой.
- Ключи чужих сервисов: где хранятся, у кого доступ, срок, как ротировать.

## 17. CORS, Host, кэш, домены (A02)

- **CORS:** `Access-Control-Allow-Origin` отражает любой `Origin` вместе с `Allow-Credentials: true` — любой сайт читает данные пользователя. Также `null`, проверка по `endswith("example.com")` (пропускает `evilexample.com`), regex без якорей.
- **Host-заголовок:** абсолютные ссылки (письма, редиректы, canonical) строятся из настроек, не из `Host`/`X-Forwarded-Host`; приложение отвечает только на свои имена.
- **Кэш:** web cache poisoning через непривязанные к ключу заголовки (`X-Forwarded-Host`, `X-Original-URL`); cache deception — личные страницы по адресу с «статичным» расширением.
- **Поддомены:** CNAME на удалённые сервисы (Heroku, GitHub Pages, S3, Netlify, старые хостинги) — subdomain takeover; A-записи на освобождённые IP.
- **Почта домена:** SPF, DKIM, DMARC (`p=quarantine`/`reject`) — против подделки писем от вашего имени.

## 18. Цепочка поставок (A03)

- Уязвимые зависимости: `pip-audit` / `uv pip` + `osv-scanner`, `npm audit` / `pnpm audit`, `composer audit`, плагины и ядро WordPress/Bitrix — версии против баз уязвимостей.
- Lock-файлы в репозитории и установка строго по ним (`uv sync --frozen`, `npm ci`, `composer install`).
- Тайпсквоттинг и подмена: опечатки в именах пакетов, пакеты без истории, `postinstall`-скрипты, внутренние имена, доступные в публичном реестре (dependency confusion).
- Скрипты с CDN: точная версия + `integrity` (SRI) + `crossorigin`; лучше локальная копия.
- CI/CD (GitHub Actions): действия закреплены по SHA, не по тегу; `pull_request_target` не запускает код из PR с секретами; минимальные `permissions:`; секреты не печатаются; автодеплой по пушу — кто может пушить в ветку.
- Происхождение образов Docker, базовые образы обновляются; `trivy image`.

## 19. Обработка ошибок (A10)

- Трассировки, SQL, пути и версии не показываются пользователю (`DEBUG=False`, `display_errors=Off`, `APP_DEBUG=false`); страницы ошибок не отражают ввод.
- **Fail open:** исключение в проверке прав, подписи, лимита, второго фактора не должно пропускать дальше. Ищи `except: pass`, `catch {}` вокруг проверок, `return True` в `except`.
- Ошибка внешнего сервиса (Telegram, почта, платёжка) не ломает безопасность: не выключает второй фактор «раз код не отправился», не открывает доступ.
- Частично выполненные операции откатываются (транзакции).

## 20. Журнал и оповещения (A09)

- В журнал: входы и неудачи, смена пароля/2FA/ролей, просмотр и изменение секретов, удаления, экспорт, ошибки прав (403), срабатывание лимитов. С временем, пользователем, IP, устройством.
- Журнал нельзя править из приложения обычной ролью; хранится достаточно долго; есть оповещения о подозрительном (серия неудачных входов, вход с нового устройства, массовый просмотр секретов).
- В журнал не пишутся секреты; ввод в журнале экранируется при показе.

## 21. Сервер и конфигурация (A02)

- Открытые порты (`ss -ltnp`): БД, Redis, панели, Docker API, debug-серверы слушают только `127.0.0.1` или закрыты файрволом. Origin за Cloudflare принимает 80/443 только с IP Cloudflare (иначе обходят WAF прямо по IP).
- SSH: только ключи, без пароля root, ограничение частоты; лишние ключи в `authorized_keys`.
- Обновления ОС и автообновления безопасности; нужна ли перезагрузка (новое ядро).
- Права файлов: `.env`/конфиги — `600`, владелец — пользователь службы; служба не под root; код недоступен на запись веб-процессу (кроме папок загрузки).
- Бэкапы зашифрованы, не в веб-корне, восстановление проверено.
- Служебные страницы закрыты: `/docs`, `/openapi.json`, `/redoc` (FastAPI в проде), `/adminer`, `/phpmyadmin`, `/server-status`, `/actuator`, `/.well-known` без лишнего, `/debug`, `/_profiler`, `/graphql` introspection.
- Заголовки: `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`; без `Server`/`X-Powered-By` с версиями.
- TLS: только 1.2+, сертификат и цепочка, редирект http→https, HSTS.
- Docker: не монтировать `docker.sock` в контейнеры приложений, не `--privileged`, секреты не в образах.
- `robots.txt` закрывает админку от индексации (но не является защитой).

## 22. LLM, боты, AI-агенты

Если бэкенд вызывает LLM с внешними данными (письма, сообщения клиентов, страницы сайтов, документы):
- **Prompt injection:** текст клиента «игнорируй инструкции и …» может сменить поведение. Модели не давать инструменты с побочными эффектами (отправка, удаление, оплата, доступ к CRM) без проверки на стороне кода; ответы модели — недоверенный ввод (экранировать, валидировать JSON, не выполнять как код/SQL).
- Утечка системного промпта и данных других клиентов через контекст; не класть секреты в промпт.
- Лимиты расходов и частоты на пользователя/диалог; ключ API на сервере, не во фронте.
- Вывод модели в HTML/Telegram — через экранирование (раздел 8).

## 23. WordPress

- Ядро, плагины, темы — актуальные версии; брошенные плагины удалить (не только отключить).
- `wp-config.php` вне доступа, `DISALLOW_FILE_EDIT`, ключи соли заданы; `debug.log` не в публичном `wp-content`.
- Перечисление пользователей: `/?author=1`, `/wp-json/wp/v2/users` — закрыть для гостей.
- `xmlrpc.php` выключить, если не нужен (перебор паролей `system.multicall`).
- В `wp-content/uploads` запрещено выполнение PHP.
- Свои ajax/REST-обработчики: `check_ajax_referer`/nonce **и** `current_user_can`, `$wpdb->prepare`, `esc_html/esc_attr/esc_url` при выводе, `sanitize_*` при вводе, `wp_safe_redirect`.
- Логи лидов и форм не лежат публично в теме/uploads.

## 24. Bitrix

- Ядро и модули обновлены; модуль «Проактивная защита» включён (WAF, контроль активности), «Сканер безопасности» без критичных.
- Не остались установщики и восстановление: `bitrixsetup.php`, `restore.php`, `/bitrix/backup/` с публичным доступом, дампы в корне.
- `/bitrix/admin/` — сильные пароли, 2FA для админов, ограничение по IP при возможности; группа «Администраторы» — минимум людей.
- `.settings.php`/`dbconn.php` — права, без доступа извне; `exception_handling` → `debug=false`.
- Свои компоненты и `ajax.php`: `check_bitrix_sessid()`, проверка прав, `$DB->ForSql`/ORM, `htmlspecialcharsbx` при выводе, без `include` по параметру.
- Старые демо-страницы и тестовые скрипты разработчиков в корне.

## 25. Мобильное приложение и его API

- Всё, что проверяет приложение, повторно проверяет сервер; ключи в приложении считаются публичными.
- Старые версии API для старых сборок — с теми же проверками прав (API9).
- Хранилища файлов (S3/Spaces/R2): приватные бакеты, подписанные ссылки с коротким сроком, нет публичного листинга, CORS бакета по белому списку.
- Push-токены и deep links не дают действий без входа.

## 26. Свежие уязвимости платформ (проверять версии, а не код)

Код проекта может быть чистым, а сервер — дырявым из-за версии PHP, Java, SSH, CMS. **Перед каждым аудитом искать свежие публикации** (WebSearch, режим extended: «critical vulnerability actively exploited <месяц год> CISA KEV», «<стек> RCE <год>») и сверять с версиями на серверах. Известные на ноябрь 2026:

| Имя | CVE | Что | Исправлено в | Как проверить |
|---|---|---|---|---|
| **PHP2Shell** (окт. 2026, эксплуатируется, CISA KEV) | CVE-2026-109618, CVE-2026-109619 | RCE без входа в самом PHP 5.4–8.5 (обработка нехватки памяти; session upload progress). Обновление CMS не помогает | PHP 8.5.12, 8.4.27, 8.3.36, 8.2.35; для 7.4/8.0/8.1 — только бэкпорт сборщика (Ondřej Surý, Plesk, Remi, хостер) | `php -v` у **каждой** версии (`/usr/bin/php*`, `/opt/plesk/php/*/bin/php`); для старых веток — changelog пакета на CVE (`zcat /usr/share/doc/php7.4-fpm/changelog.Debian.gz \| grep CVE-2026-10961`); **php-fpm/httpd перезапущены позже установки пакета** (`rpm -q --last php-common` / `ls -l --time-style=full-iso /var/lib/dpkg/info/php*-common.list` против `ps -o lstart= -p $(pgrep -o php-fpm)`); снаружи — заголовок `X-Powered-By`. Временно: `session.upload_progress.enabled=0` |
| **phpAfterShell** (19.11.2026, CVSS 9.2, эксплуатации пока не видели) | CVE-2026-126714 | Прерванная запись файла сессии оставляет смесь старых и новых данных → `session_start()` десериализует подложенный объект → RCE (в цепочке с порчей памяти во встроенном классе PHP). Нужен штатный `session.save_handler = files`; проще всего через session upload progress. **Патч PHP2Shell не закрывает** | PHP 8.5.13, 8.4.28, 8.3.37, 8.2.36, 8.6.0 (в них upload progress выключен по умолчанию); 7.4/8.0/8.1 — только сборки-бэкпорты с выключенным upload progress (Surý, Plesk); дистрибутивы — по changelog (Ubuntu `zcat …/php8.3-common/changelog.Debian.gz \| grep -c 126714`) | версия и настройки **того PHP, что отдаёт сайт**, а не CLI: `php-fpmX.Y -i \| grep -E 'upload_progress.enabled\|save_handler'` для каждой версии, mod_php — `php -i` той же сборки, плюс `php_admin_flag`/`php_value` в пулах и `.user.ini`. Затронуто: `files` + `upload_progress.enabled = On` + версия ниже исправленной. Временно (если сайт не показывает прогресс загрузки): `session.upload_progress.enabled = 0` в php.ini/пуле + перезапуск php-fpm/httpd — закрывает лишь самый простой путь; сессии в Redis/memcached/БД этой ошибкой не задеты |
| **Java4Shell** (нояб. 2026) | CVE-2026-114938 | Порча памяти в Base64-декодере OpenJDK → RCE без входа (Jira, Jenkins, Keycloak…). Только x86-64 с AVX-512 VBMI | сборки OpenJDK от 17.11.2026 для 17/21/25/27; ветки 18–20, 22–24, 26 — переходить на поддерживаемую. Java 8 и 11 не затронуты | `java -version` на хосте и **внутри контейнеров** (`docker exec … java -version`), `grep -o avx512vbmi /proc/cpuinfo \| head -1` |
| **SSHole** (нояб. 2026, эксплуатируется, CISA KEV) | CVE-2026-123158 | Обход входа в OpenSSH на **musl** (Alpine) без PAM: любой пароль 257–1024 символов | OpenSSH 10.6p2 + перезапуск sshd | `ldd --version` (glibc — не затронут; musl — затронут), `ssh -V`; Alpine-контейнеры с sshd |
| OpenSSH GSSAPI (март 2026, патч дистрибутивов) | CVE-2026-3497 | Чтение неинициализированной памяти в GSSAPI key exchange (патч RHEL/Debian/Ubuntu/SUSE, не upstream) | пакеты дистрибутивов (RHEL 9: `openssh-9.9p1-16.el9` и новее, Debian DSA-6204-1) | `sshd -T \| grep -i gssapikeyexchange` (`no` — недостижимо), `dnf check-update openssh` / `apt list --upgradable \| grep openssh`; временно `GSSAPIKeyExchange no` |
| OpenSSH прочие 2026 | CVE-2026-35386/35387/35388 (<10.3), 59999/60001/60002 (<10.4) | в основном клиент ssh и мелкие обходы настроек (`DisableForwarding`, задержка входа) | 10.3/10.4 или бэкпорт дистрибутива | обновления пакета; на сервере в любом случае: `PasswordAuthentication no`, `PermitRootLogin prohibit-password`/`no`, ограничение частоты (ufw limit / fail2ban), sshd перезапущен после обновления (`ps -o lstart= -p $(pgrep -o sshd)`) |
| **wp2shell** (июль 2026, эксплуатируется) | CVE-2026-63030 + CVE-2026-60137 | RCE без входа в ядре WordPress: путаница в REST batch + SQL-инъекция в WP_Query | WordPress 6.9.5, 7.0.2, 7.1 | `wp core version`, `wp-includes/version.php`; следы — новые админы, файлы в uploads |

Также в ноябре 2026 в KEV: Synology DSM/BeeStation, LiteLLM, Apache Axis 1.x, Apache Roller, Puppet Enterprise, Check Point, UnrealIRCd — проверить, если что-то из этого есть в инфраструктуре (особенно Synology NAS с бэкапами).

Скрипт сверки версий (только чтение, одно подключение на сервер):

```bash
cat > vers.sh <<'EOF'
echo "OS: $(. /etc/os-release 2>/dev/null; echo $PRETTY_NAME) | $(uname -r)"
echo "SSH: $(ssh -V 2>&1) | libc: $(ldd --version 2>&1 | head -1)"
for p in $(ls /usr/bin/php /usr/bin/php[0-9]* /usr/local/bin/php /opt/plesk/php/*/bin/php /opt/php*/bin/php 2>/dev/null | sort -u); do echo "PHP $p: $($p -v 2>/dev/null | head -1)"; done
# PHP, который реально отдаёт сайты: у CLI и FPM разные php.ini (phpAfterShell, PHP2Shell)
for b in $(ls /usr/sbin/php-fpm* /opt/plesk/php/*/sbin/php-fpm /opt/remi/*/root/usr/sbin/php-fpm /opt/*/sbin/php-fpm 2>/dev/null | sort -u); do
  echo "FPM $b: $($b -v 2>/dev/null | head -1 | cut -c1-30) | $($b -i 2>/dev/null | grep -E '^session\.(save_handler|upload_progress\.enabled) ' | awk '{print $1"="$NF}' | tr '\n' ' ')"; done
ps -eo args | grep -E 'php-fpm: master' | grep -v grep
(ls /etc/apache2/mods-enabled/ 2>/dev/null | grep -E '^php.*load'; httpd -M 2>/dev/null | grep -i php) | sed 's/^/MOD_PHP /'
command -v java >/dev/null && echo "JAVA: $(java -version 2>&1 | head -1)"
command -v docker >/dev/null && docker ps --format 'DOCKER {{.Names}} {{.Image}}' 2>/dev/null
EOF
ssh -o BatchMode=yes user@host 'bash -s' < vers.sh
```

---

## Живые проверки (безопасные, одиночные, только свои сайты)

```bash
H=https://example.com
curl -sI $H/ | grep -iE '^(strict|content-security|x-frame|x-content|referrer|permissions|server|x-powered)'
curl -sI http://example.com/ | head -3                       # редирект на https
for p in .env .git/HEAD .git/config backup.zip dump.sql phpinfo.php composer.json package.json \
         docs openapi.json redoc adminer.php phpmyadmin/ server-status wp-config.php.bak \
         bitrixsetup.php restore.php bitrix/backup/ xmlrpc.php "wp-json/wp/v2/users" "?author=1"; do
  printf '%s %s\n' "$(curl -s -o /dev/null -w '%{http_code}' "$H/$p")" "$p"; done
curl -s "$H/login?e=ZZTEST123&m=ZZTEST123&message=ZZTEST123&error=ZZTEST123" | grep -c ZZTEST123   # 0 = не отражается
curl -s "$H/?q=%3Cb%3EZZ%3C%2Fb%3E" | grep -c '<b>ZZ</b>'    # 0 = экранируется
curl -sI -H 'Origin: https://evil.example' $H/api/ | grep -i access-control   # не должно отражать evil
curl -sI -H 'Host: evil.example' $H/ | head -3                # не должен отвечать сайтом / строить ссылки на evil
curl -s -o /dev/null -w '%{http_code}\n' "$H/redirect?next=//evil.example"   # не 30x на evil
```

На сервере (по SSH, только чтение): `ss -ltnp`, `ufw status`, `ls -la` конфигов, `journalctl -u <служба> --since -2d | grep -ciE 'password|token|secret'` (только счёт), версии пакетов, `last`/`lastb` по желанию.

Активное сканирование (nuclei, ZAP active, sqlmap, перебор) — **только с явного согласия владельца**, на своём сервере, не в часы пик; чужие сайты не трогать.

## Инструменты

| Задача | Python | PHP | Node | Общие |
|---|---|---|---|---|
| Статический анализ | `bandit -r .`, `semgrep --config p/python` | `semgrep --config p/php`, `phpstan` + security rules, WPScan (WP) | `semgrep --config p/javascript`, `eslint-plugin-security` | `semgrep --config p/owasp-top-ten` |
| Зависимости | `pip-audit`, `osv-scanner` | `composer audit`, WPScan | `npm audit`, `osv-scanner` | `trivy fs .` |
| Секреты | `gitleaks detect`, `trufflehog git file://.` | | | |
| Живой сайт | `testssl.sh`, ZAP baseline (`zap-baseline.py -t URL`, пассивный), Mozilla Observatory | | | |

Установка через `uvx`/`npx`/`brew` во временную папку; результаты сканеров проверять чтением кода — ложные срабатывания частые.

## Тесты (регрессия после исправлений)

Каждая найденная дыра → тест, который воспроизводит атаку и ждёт отказа. Шаблоны (pytest + TestClient; для PHP — PHPUnit/HTTP-клиент, для Node — supertest):

```python
def test_idor_other_users_record(client_a, record_of_b):        # 3. BOLA
    assert client_a.get(f"/orders/{record_of_b.id}").status_code in (403, 404)
    assert client_a.post(f"/orders/{record_of_b.id}/delete", data={"csrf": csrf(client_a)}).status_code in (403, 404)

def test_mass_assignment_ignored(client_user):                  # 4
    client_user.post("/profile", data={"csrf": csrf(client_user), "name": "x", "role": "admin", "is_admin": "1"})
    assert db.val("SELECT role FROM users WHERE id=?", client_user.uid) != "admin"

def test_sql_injection_in_search(client):                       # 1
    r = client.get("/e/sites", params={"q": "' OR 1=1 --"})
    assert r.status_code == 200 and "ожидаемая чужая запись" not in r.text

def test_csrf_required(client):                                 # 10
    assert client.post("/settings", data={"x": "1"}).status_code in (400, 403)

def test_open_redirect(client):                                 # 10
    for bad in ("//evil.example", "https://evil.example", "/\\evil.example", "\\\\evil.example"):
        loc = client.post("/action", data={"csrf": csrf(client), "back": bad}, follow_redirects=False).headers["location"]
        assert not loc.startswith(("//", "http", "\\")) and "evil" not in loc.split("?")[0]

def test_xss_escaped(client):                                   # 8
    client.post("/e/sites/new", data={"csrf": csrf(client), "domain": "<script>alert(1)</script>"})
    assert "<script>alert(1)</script>" not in client.get("/e/sites").text

def test_reflected_text_not_shown(client):                      # 9
    assert "ZZTEST" not in client.get("/login?e=ZZTEST&m=ZZTEST").text

def test_login_rate_limit(client):                              # 7
    codes = [client.post("/login", data={"login": "a", "password": str(i)}).status_code for i in range(10)]
    assert "Слишком много попыток" in client.post("/login", data={"login": "a", "password": "x"}, follow_redirects=True).text

def test_session_revoked_after_password_change(client_a, client_a_other_device): ...   # 7
def test_secret_not_in_api_response(client): assert "password_hash" not in client.get("/api/me").text   # 6
def test_path_traversal(client):                                # 11
    for p in ("../../etc/passwd", "..%2f..%2fetc%2fpasswd", "/etc/passwd"):
        assert client.get(f"/files/{p}").status_code in (400, 403, 404)

def test_ssrf_blocked():                                        # 12
    for url in ("http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "http://[::1]/",
                "http://2130706433/", "file:///etc/passwd", "gopher://127.0.0.1:6379/"):
        with pytest.raises(BlockedURL):
            safe_fetch(url)

def test_race_single_use_code(client):                          # 14 — параллельно
    import concurrent.futures as cf
    with cf.ThreadPoolExecutor(20) as ex:
        ok = sum(r.status_code == 200 for r in ex.map(lambda _: client.post("/redeem", data={"code": CODE}), range(20)))
    assert ok == 1

def test_webhook_signature(client):                             # 16
    assert client.post("/webhook/pay", content=b'{"paid":true}', headers={"X-Signature": "bad"}).status_code in (401, 403)

def test_security_headers(client):                              # 21
    h = client.get("/login").headers
    assert "default-src" in h["content-security-policy"] and h["x-content-type-options"] == "nosniff"

def test_no_debug_routes(client):                               # 21
    for p in ("/docs", "/openapi.json", "/redoc"):
        assert client.get(p).status_code == 404
```

Тесты должны проходить в CI, и при добавлении нового маршрута — дописываться (особенно IDOR и CSRF: удобно сделать один параметризованный тест по списку всех маршрутов приложения, который проверяет, что без сессии — редирект на вход, без CSRF — 403, чужая запись — 403/404).

## Формат отчёта

```
| # | Раздел | Как в проекте | Вердикт |
|---|---|---|---|
| 1 | SQL-инъекция | параметры везде; имена таблиц — из словаря сущностей | ✅ |
| 3 | IDOR | /api/files/{id} не проверяет владельца (app.py:412) | ❌ высокая |
| 11 | Загрузка файлов | нет в проекте | — |
…
```

Затем — каждая проблема: файл:строка, сценарий атаки одной фразой («пользователь A меняет id в адресе и скачивает договор B»), предложенный фикс, серьёзность (критическая / высокая / средняя / низкая). Мелочи и сознательные компромиссы (например, общий лимит попыток входа на 15 минут закрывает вход и владельцу; SSRF в мониторинге как функция для администраторов) — отдельным списком, без преувеличения. В конце — что проверено только по коду, а что подтверждено на живом сервере.

## Правила

- Аудит — только чтение. Правки кода — после согласия пользователя; выкладка на сервер и любые записи на прод — только после явного разрешения на каждое конкретное действие.
- Не печатать секреты, токены, пароли, ключи — ни из кода, ни из логов, ни из БД. Сравнивать по хэшу, считать совпадения.
- Чужие сайты не атаковать; на своих — единичные безопасные запросы, активное сканирование только с согласия.
- Найденный утёкший секрет — сообщить и предложить ротацию, а не только удаление из кода.
- После исправления — тест, который воспроизводит атаку и проверяет, что она больше не проходит.
