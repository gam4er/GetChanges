# GCNet

GCNet — консольный инструмент для мониторинга изменений в Active Directory через LDAP-уведомления (`DirectoryNotificationControl`) с выводом событий в JSON-массив, совместимый с дальнейшей аналитикой (в т.ч. в стиле BloodHound-пайплайнов).

Этот README описывает **только основной проект `GCNet`**.

---

## Что делает GCNet

GCNet подключается к домену от имени текущего пользователя, подписывается на поток изменений в заданном Base DN и пишет события в файл.

Ключевые возможности:

- непрерывный мониторинг изменений AD-объектов в subtree;
- запись «сырых» изменений в JSON;
- выборочная фильтрация по отслеживаемым атрибутам;
- расчёт `old/new` для отслеживаемых атрибутов через baseline-снимок;
- опциональное обогащение события метаданными репликации (`msDS-ReplAttributeMetaData`).

---

## Принцип работы (по шагам)

### 1) Старт и разбор параметров

Точка входа — `GCNet/GCNet.cs`.
CLI-параметры описаны в `GCNet/Options.cs` через `CommandLineParser`.

### 2) LDAP-подключение

`LDAPSearches.InitializeConnection()`:

- определяет текущий AD-домен через `IPGlobalProperties.GetIPGlobalProperties().DomainName`;
- создаёт `LdapConnection`;
- включает:
  - `ProtocolVersion = 3`,
  - `AuthType = Negotiate`,
  - `AutoReconnect = true`,
  - `ReferralChasing = None`,
  - `AutoBind = true`,
  - `LocatorFlag = KdcRequired | PdcRequired`;
- выполняет `Bind()`.

### 3) Выбор области мониторинга

В `ChangeMonitorApplication.Run()`:

- если передан `--base-dn`, используется он;
- иначе берётся `defaultNamingContext` через `GetBaseDn()` (запрос к RootDSE).

Важно: выбранный DN в обоих случаях — это **стартовая база LDAP-запроса** (`baseDn` в `SearchRequest`), от которой начинается подписка.

### 4) Подготовка baseline (если включён список tracked-атрибутов)

Если задан `--tracked-attributes`, приложение:

- строит начальный снимок объектов (`LoadBaseline(...)`),
- хранит snapshot в `ConcurrentDictionary<Guid, BaselineEntry>`.

Это нужно, чтобы на лету понимать, изменился ли интересующий атрибут, и формировать пары `<attr>_old` / `<attr>_new`.

### 5) Подписка на LDAP-уведомления об изменениях

`StartNotification(...)` формирует `SearchRequest` с:

- фильтром `(objectClass=*)`;
- `SearchScope.Subtree`;
- атрибутами `*` и `objectGUID`;
- контролами:
  - `DirectoryNotificationControl`,
  - `DomainScopeControl`,
  - `1.2.840.113556.1.4.417` (show deleted),
  - `1.2.840.113556.1.4.2064` (show recycled),
  - `SearchOptionsControl(SearchOption.PhantomRoot)` **только при `--phantom-root`**.

Пояснение по `SearchOption.PhantomRoot`:

- включает режим виртуального корня (PhantomRoot) на подключённом DC;
- фактический охват поиска может выходить за пределы одного naming context (NC);
- это **не** гарантия «всех контекстов всего леса на всех DC»;
- итоговый набор событий зависит от того, к какому DC вы подключены, и от прав учётной записи.

Далее запускается `BeginSendRequest(... ReturnPartialResultsAndNotifyCallback ...)`, и каждый `SearchResultEntry` поступает в очередь обработки.

### 6) Конвейер обработки событий

`ChangeProcessingPipeline`:

- вход: `BlockingCollection<ChangeEvent>`;
- выход: `BlockingCollection<Dictionary<string, object>>`.

Логика:

1. Проверка, нужно ли писать событие:
   - если tracked-атрибуты не заданы — пишется всё;
   - если заданы — событие пишется только при изменении хотя бы одного tracked-атрибута.
2. Для tracked-режима всегда добавляются поля `<attr>_old` / `<attr>_new`.
3. Если включён `--enrich-metadata`, добавляется `msdsReplAttributeMetaData`.
4. Событие передаётся в writer-очередь.

### 7) Запись результата

`JsonArrayFileWriter`:

- открывает JSON-массив (`[`),
- последовательно сериализует объекты,
- при завершении закрывает массив (`]`).

Файл всегда остаётся валидным JSON при штатном завершении.

---

## Ключевые параметры запуска

`GCNet/Options.cs`:

- `-o, --output` — путь к выходному JSON (по умолчанию `result.json`)
- `--base-dn` — корневой DN для поиска (если не указан, берётся `defaultNamingContext`)
- `--enrich-metadata` — включить обогащение `msDS-ReplAttributeMetaData`
- `--tracked-attributes` — список атрибутов через запятую; включает режим фильтрации/диффа
- `--dn-ignore-list` — путь к файлу с DN-фильтрами для игнорирования (по умолчанию `dn-ignore-default.txt`, см. `DefaultDnIgnoreListPath`)
- `--phantom-root` — добавить `SearchOptionsControl(SearchOption.PhantomRoot)` в notification search
- `--dc` — явный FQDN контроллера домена для LDAP-подключения
- `--dc-selection` — режим выбора DC:
  - `auto` (по умолчанию) — автоматический выбор здорового DC; если одновременно задан `--dc`, он используется как fallback;
  - `manual` — принудительно использовать `--dc`; при `--dc-selection=manual` параметр `--dc` обязателен.
- `--prefer-site-local` — при `--dc-selection=auto` предпочитать здоровые DC из локального AD-сайта (по умолчанию `true`)

Поведение по умолчанию:

- `--dn-ignore-list` по умолчанию указывает на `dn-ignore-default.txt` (`DefaultDnIgnoreListPath`). Если файла нет, он создаётся автоматически с шаблонным комментарием.
- `--dc-selection` по умолчанию `auto`; `manual` требует обязательный `--dc`.
- `--prefer-site-local` по умолчанию включён (`true`) и влияет на ранжирование кандидатов DC в `auto`-режиме.

Пример:

```bash
GCNet.exe --base-dn "DC=corp,DC=local" --tracked-attributes "member,adminCount,userAccountControl" --enrich-metadata -o changes.json
```

Дополнительные примеры:

```bash
# manual DC selection (обязателен --dc)
GCNet.exe --dc-selection manual --dc dc01.corp.local --base-dn "DC=corp,DC=local" -o changes-manual.json

# auto mode с fallback на --dc
GCNet.exe --dc-selection auto --dc dc-fallback.corp.local --prefer-site-local --phantom-root -o changes-auto.json
```

---

## Формат событий (концептуально)

События представляют собой объект `Dictionary<string, object>`, полученный из `SearchResultEntry`.
В зависимости от режима вы увидите:

- базовые LDAP-атрибуты объекта;
- при tracked-режиме:
  - `<attribute>_old`
  - `<attribute>_new`
- при metadata-режиме:
  - `msdsReplAttributeMetaData` (массив словарей с полями вроде `attributeName`, `version`, `lastChangeTime`, `changedBy`, `raw`).

---

## Важные принципы и ограничения

1. **GCNet — near-real-time монитор**, а не форензик-хранилище:
   качество потока зависит от доступности DC, прав и стабильности LDAP-сеанса.

2. **Tracked-режим завязан на baseline в памяти**:
   после рестарта baseline пересобирается заново.

3. **Case-insensitive сопоставление атрибутов**:
   pipeline пытается корректно сопоставлять ключи атрибутов вне зависимости от регистра.

4. **Сериализация значений в canonical JSON**:
   сравнение изменений выполняется через JSON-представление значения.

5. **Завершение по ENTER**:
   приложение работает до ручной остановки (нажатие ENTER в консоли).

---

## Требования к среде

- Windows/AD-среда с доступом к LDAP домена;
- .NET Framework 4.8 (см. `GCNet.csproj`);
- учётная запись с правами на чтение нужной области каталога и атрибутов;
- сетевой доступ к контроллерам домена.

---

## Сборка

Проект: `GCNet/GCNet.csproj`.
Решение: `GetChanges.sln`.

Типовой сценарий:

1. восстановить NuGet-пакеты;
2. собрать `Release` конфигурацию;
3. запустить `GCNet.exe` с нужными флагами.

---

## Модули проекта GCNet

- `GCNet.cs` — entrypoint и запуск приложения;
- `Options.cs` — CLI-опции;
- `ChangeMonitorApplication.cs` — orchestration жизненного цикла (connect → monitor → stop);
- `ChangeProcessingPipeline.cs` — фильтрация, diff tracked-атрибутов, enrichment, маршрутизация в output;
- `MetadataEnricher.cs` — загрузка и парсинг `msDS-ReplAttributeMetaData`;
- `LDAPSearches.cs` — LDAP utility-методы и инициализация подключения;
- `JsonArrayFileWriter.cs` — потоковая запись валидного JSON-массива;
- `ChangeModels.cs` — модели `ChangeEvent`, `BaselineEntry`.

---

## Безопасность и эксплуатационные замечания

- Приложение пишет потенциально чувствительные атрибуты AD в файл — храните output как чувствительные данные.
- В `InitializeConnection()` отключена проверка серверного сертификата (`VerifyServerCertificate => false`) — учитывайте это в защищённых контурах и при аудитах.
- При мониторинге больших областей DN поток событий может быть высоким; закладывайте место на диске и контролируйте ротацию файлов на стороне эксплуатации.

---

## Краткий сценарий использования

1. Определите область (`--base-dn`).
2. Решите, нужен ли full-stream или только tracked-изменения (`--tracked-attributes`).
3. При необходимости включите метаданные (`--enrich-metadata`).
4. Запустите и оставьте процесс работать.
5. Для остановки нажмите ENTER.
6. Передайте JSON в ваш аналитический пайплайн.
