# GetChanges (ветка framework)

GetChanges — консольная утилита для Windows, которая отслеживает изменения объектов Active Directory через LDAP **persistent search** и записывает каждое подходящее изменение в отдельный JSON-файл с отступами в локальный каталог. Эта ветка `framework` нацелена на **.NET Framework 4.8** для окружений, где невозможно использовать .NET 10 (современный вариант живёт в `devel`).

> Все глубокие ссылки в этом документе указывают на ветку `framework` на GitHub. Если номера строк сдвигаются, обновляйте ссылки вместе с кодом (см. [AGENTS.md](AGENTS.md)).

---

## 1. Что делает приложение — кратко

1. Обнаруживает (или принимает) лучший контроллер домена, выполняет аутентифицированный bind `LdapConnection` и кеширует выбранный DC на всё время жизни процесса.
2. Опционально предзагружает **базовый снимок** отслеживаемых атрибутов для каждого объекта под корнем поиска — это нужно, чтобы подавлять уведомления, которые на самом деле не меняют отслеживаемый атрибут.
3. Запускает один LDAP persistent search (`DirectoryNotificationControl`) и асинхронно потребляет инкрементальные записи об изменениях.
4. Отфильтровывает DN по списку игнорирования; оставшиеся разбираются в property-bag.
5. Прогоняет события через небольшой in-process **producer/consumer pipeline** (две неограниченные очереди `BlockingCollection<>`).
6. Опционально обогащает события `msDS-ReplAttributeMetaData` от DC.
7. Записывает каждое подходящее событие в отдельный JSON-файл с timestamp через файловый sink с одним писателем.
8. Обновляет живую строку статуса Spectre.Console со счётчиками уведомлений и записей; переподключается с экспоненциальным backoff с верхней границей и jitter при временных ошибках LDAP, а также форсирует повторное обнаружение DC при каждом переподключении.

---

## 2. Быстрый старт

```powershell
# VS 2022 Developer PowerShell
& 'C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\Launch-VsDevShell.ps1' -SkipAutomaticLocation

# Восстановите packages.config (msbuild restore НЕ обрабатывает packages.config-проекты)
Invoke-WebRequest https://dist.nuget.org/win-x86-commandline/latest/nuget.exe `
  -OutFile "$env:USERPROFILE\.nuget\nuget.exe"
& "$env:USERPROFILE\.nuget\nuget.exe" restore GetChanges.sln

# Сборка
msbuild GetChanges.sln /p:Configuration=Release /v:minimal

# Запуск
GCNet\bin\Release\GCNet.exe --base-dn "DC=corp,DC=local"
GCNet\bin\Release\GCNet.exe --help

# Отслеживать изменения только DACL/Owner/Group для всех объектов
GCNet\bin\Release\GCNet.exe --base-dn "DC=corp,DC=local" --track-nt-security-descriptor

# Совмещение с другими отслеживаемыми атрибутами (наличие nTSecurityDescriptor в списке неявно включает SD-трекинг)
GCNet\bin\Release\GCNet.exe --base-dn "DC=corp,DC=local" --tracked-attributes "nTSecurityDescriptor,memberOf"
```

Нажмите **ENTER** или **CTRL+C**, чтобы остановить мониторинг чисто (кооперативная отмена, затем ограниченные ожидания — см. [`MonitoringLifecycleService`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/MonitoringLifecycleService.cs#L24)).

---

## 3. Требования

- Windows со встроенным рантаймом .NET Framework 4.8.
- Visual Studio 2022 + MSBuild 17.x (редакция Build Tools тоже подходит).
- Доменная учётка с правом читать каталог и (если используется `--enrich-metadata`) `msDS-ReplAttributeMetaData`.
- Для `--track-nt-security-descriptor`: той же учётке нужно право `READ_CONTROL` на отслеживаемые объекты, чтобы прочитать Owner/Group/DACL. SACL намеренно не запрашивается (потребовал бы `SeSecurityPrivilege` и выходит за рамки задачи).
- Сетевой доступ по LDAP/LDAPS как минимум до одного DC.

---

## 4. Справка по CLI

Все опции определены в [`Hosting/Options.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/Options.cs#L8):

| Опция | Описание |
| --- | --- |
| `--base-dn <DN>` | Корень поиска. По умолчанию — `defaultNamingContext`. |
| `--enrich-metadata` | Прикреплять `msDS-ReplAttributeMetaData` к каждому событию. |
| `--tracked-attributes a,b,c` | Список атрибутов через запятую. Если задан, файл создаётся только при изменении этих атрибутов; на старте загружается базовый снимок. Указание `nTSecurityDescriptor` в этом списке неявно включает `--track-nt-security-descriptor`. |
| `--track-nt-security-descriptor` | Отслеживать изменения `nTSecurityDescriptor` (Owner \| Group \| DACL). Добавляет `nTSecurityDescriptor` в список запрашиваемых атрибутов и прикладывает `LDAP_SERVER_SD_FLAGS_OID` (`1.2.840.113556.1.4.801`) с маской `Owner \| Group \| Dacl`. Дескриптор хранится в виде SDDL-строки для устойчивого diff. SACL **не** запрашивается. |
| `--dn-ignore-list <path>` | Файл с подстрочными фильтрами DN (по одному на строку). По умолчанию: `dn-ignore-default.txt`. |
| `--output-dir <path>` | Каталог для JSON-событий. По умолчанию: `.\output`. |
| `--phantom-root` | Включает `SearchOption.PhantomRoot` для persistent search. |
| `--dc <fqdn>` | Принудительно использовать конкретный DC (комбинируйте с `--dc-selection manual`). |
| `--dc-selection auto\|manual` | Стратегия выбора DC. По умолчанию: `auto`. |
| `--prefer-site-local` | Предпочитать здоровые DC из локального AD-сайта. По умолчанию: `true`. |

---

## 5. Архитектура

```
                +--------------------------+
                |  GetChanges.Main         |  Hosting/GetChanges.cs
                |  (Spectre.Console.Cli)   |
                +-----------+--------------+
                            |
                            v
                +--------------------------+
                |  ChangeMonitorApplication|  Hosting/ChangeMonitorApplication.cs
                |  - валидирует опции      |
                |  - связывает подсистемы  |
                |  - владеет lifecycle/    |
                |    статусом              |
                +---+-----------+----------+
                    |           |
       +------------+           +-------------------+
       v                                            v
+-------------------+                    +-------------------------+
| LdapConnection    |                    | BaselineSnapshotLoader  |  Pipeline/BaselineSnapshotLoader.cs
| Factory           |                    | (опционально, при       |
| Ldap/             |                    | --tracked-attributes)   |
| LdapConnection    |                    +-------------------------+
| Factory.cs        |
+---------+---------+
          |
          v                                         (ChangeEvent)
+-------------------+    incoming queue    +-------------------------+    outgoing queue    +------------------+
| LdapNotification  |--------------------->| ChangeProcessing        |--------------------->| EventFileWriter  |
| LoopService       |  BlockingCollection  | Pipeline                |  BlockingCollection  | Output/          |
| Ldap/...          |                      | Pipeline/...            |                      | EventFileWriter  |
+---------+---------+                      +-------------------------+                      +------------------+
          |                                            |
          | OnNotificationReceived()                   | (фильтр по diff отслеживаемых атрибутов,
          | OnBeforeReconnect() ------> сбрасывает     |  выпускает {attr}_old / {attr}_new пары,
          |                              кэш DC        |  опциональный MetadataEnricher)
          v                                            v
   счётчики / строка статуса                  счётчики / строка статуса
```

Ключевые сквозные факты:

- **Единый namespace** `GCNet`, папки только группируют — это минимизирует churn `using`-директив.
- Две **неограниченные** in-process очереди (`incoming`, `outgoing`) развязывают LDAP-callback и дисковый I/O. См. примечание в [`ChangeProcessingPipeline`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ChangeProcessingPipeline.cs#L23).
- Только notification loop переподключается; на каждом переподключении он вызывает `OnBeforeReconnect`, который очищает кэшированное имя DC в фабрике соединений, чтобы при следующей попытке был выбран свежий DC.

---

## 6. Подсистемы

### 6.1 Точка входа и CLI ([`Hosting/GetChanges.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/GetChanges.cs#L9))

- `Main` запускает Spectre.Console.Cli `CommandApp<RunCommand>`.
- `RunCommand.Execute` оборачивает приложение в `AnsiConsole.Status(...)`, чтобы оркестратор мог обновлять живую строку статуса, и делегирует [`ChangeMonitorApplication.Run`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L41).
- Исключения верхнего уровня перехватываются и логируются через [`AppConsole.WriteException`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/AppConsole.cs#L19).

### 6.2 Оркестратор приложения ([`Hosting/ChangeMonitorApplication.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L13))

- Хранит `_baseline` `ConcurrentDictionary` и счётчики (`_notificationCount`, `_eventsWrittenCount`).
- Связывает: фабрика соединений → загрузчик baseline → pipeline → писатель → notification loop, причём [`MonitoringLifecycleService`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/MonitoringLifecycleService.cs#L16) поставляет cancellation token.
- `BuildNotificationLoopContext` регистрирует `OnBeforeReconnect = _connectionFactory.ResetCachedDomainController`, чтобы каждое переподключение форсировало свежий выбор DC — см. [строку 88](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L88).
- Строка статуса перестраивается на каждое уведомление и каждую успешную запись файла — см. [`UpdateStatus`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L172). Счётчики читаются через `Interlocked.Read` для корректного безразрывного просмотра.

### 6.3 Жизненный цикл процесса ([`Hosting/MonitoringLifecycleService.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/MonitoringLifecycleService.cs#L16))

- Создаёт `CancellationTokenSource` и сигнал останова `ManualResetEventSlim`.
- `WaitForStopSignal` слушает одновременно `ENTER` и `CTRL+C`, так что любой путь корректно завершает программу.
- `WaitForTask`/`WaitForTasks` дают оркестратору ограниченные таймауты завершения, чтобы зависший LDAP-callback не мог навсегда заблокировать выход процесса.

### 6.4 Авто-обнаружение лучшего DC ([`Ldap/DomainControllerSelector.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/DomainControllerSelector.cs#L20))

- `SelectBestDomainController(options, out reason)` сначала уважает `--dc` / `--dc-selection manual`, иначе перечисляет DC через `System.DirectoryServices.ActiveDirectory`, отдаёт предпочтение локальному AD-сайту при `--prefer-site-local` и проверяет здоровье кандидатов.
- Выбранный DC и человекочитаемая причина выбора логируются один раз.

### 6.5 Фабрика соединений и кэш DC ([`Ldap/LdapConnectionFactory.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapConnectionFactory.cs#L22))

- Кеширует выбранный DC под `_cacheLock`, поэтому обнаружение DC выполняется **один раз** при старте (и снова — только при переподключении).
- [`ResetCachedDomainController`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapConnectionFactory.cs#L36) вызывается из `OnBeforeReconnect`-callback notification loop, чтобы сбросить кэш; следующий вызов [`CreateBoundConnection`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapConnectionFactory.cs#L50) выполнит повторное обнаружение.
- Настраивает протокол v3, `AutoReconnect`, отключает referral chasing, best-effort TCP keep-alive и `AuthType.Negotiate` с `AutoBind`.
- **ЗАМЕЧАНИЕ ПО БЕЗОПАСНОСТИ:** проверка серверного сертификата отключена — см. предупреждение на [строке 85](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapConnectionFactory.cs#L85).

### 6.6 Цикл уведомлений persistent search ([`Ldap/LdapNotificationLoopService.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapNotificationLoopService.cs#L46))

- Запускает `RunAsync(NotificationLoopContext, CancellationToken)`. Каждая попытка открывает `LdapConnection`, подключает `DirectoryNotificationControl` (и опционально `SearchOptionsControl(PhantomRoot)`) и стартует callback `BeginSendRequest`, который доставляет частичные результаты в `OnPartialResults` (строка 186).
- Фильтрация по DN (`ShouldIgnoreByDn`, строка 254) отбрасывает ненужные записи до парсинга.
- Каждая прошедшая запись разбирается [`LdapEntryParser`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapEntryParser.cs) и помещается в incoming-очередь pipeline; срабатывает `OnNotificationReceived` для счётчика статуса.
- При `IsRecoverableNotificationException` (строка 272) цикл:
  1. Инкрементирует счётчик попыток.
  2. Вызывает `OnBeforeReconnect` (сбрасывает кэш DC).
  3. Спит `CalculateReconnectDelay(attempt)` — экспоненциальный рост с верхней границей 60 с и jitter, через процессно-глобальный `Random`, защищённый локом (на .NET Framework 4.8 нет `Random.Shared`).

### 6.7 Парсинг записей ([`Ldap/LdapEntryParser.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapEntryParser.cs))

- Преобразует `SearchResultEntry` в `Dictionary<string, object>` плюс `objectGUID`.
- Декодирует бинарные AD-атрибуты (SID, GUID, file-time, security descriptors) в формы, удобные для JSON / соглашений SharpHound.

### 6.8 Базовый снимок ([`Pipeline/BaselineSnapshotLoader.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/BaselineSnapshotLoader.cs#L21))

- Срабатывает только при заданном `--tracked-attributes`.
- Обходит корень поиска постраничным запросом и для каждого объекта фиксирует канонические JSON-значения отслеживаемых атрибутов через [`CanonicalValueHelper`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/CanonicalValueHelper.cs#L7).
- Сохраняет результаты в общий `ConcurrentDictionary<string, BaselineEntry>`, ключ строит [`ObjectKeyBuilder.BuildObjectKey`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ObjectKeyBuilder.cs#L9) (objectGUID при наличии, иначе SHA-хэш DN).

### 6.9 Pipeline и очереди ([`Pipeline/ChangeProcessingPipeline.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ChangeProcessingPipeline.cs#L23))

- Два экземпляра `BlockingCollection<T>` поверх `ConcurrentQueue<T>`:
  - `Incoming` — наполняется потоком LDAP-callback.
  - `Outgoing` — опустошается задачей writer'а в оркестраторе.
- [`StartAsync`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ChangeProcessingPipeline.cs#L47) потребляет `Incoming`. Для каждого события:
  1. Если задано `--tracked-attributes`, [`ShouldWriteWhenTrackedAttributesChanged`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ChangeProcessingPipeline.cs#L80) сравнивает канонический JSON каждого отслеживаемого атрибута с baseline; обновляет baseline; выпускает пары `{attr}_old` / `{attr}_new` только при реальном изменении.
  2. Если задано `--enrich-metadata`, вызывает `MetadataEnricher.TryLoadMetadata`.
  3. Помещает итоговый property-bag в `Outgoing`.

### 6.10 Обогащение метаданными ([`Ldap/MetadataEnricher.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/MetadataEnricher.cs#L20))

- Лениво держит приватный `LdapConnection` (соединение пользователя зарезервировано под persistent search).
- Читает `msDS-ReplAttributeMetaData` для изменённого объекта и парсит каждую XML-запись.
- Сбрасывает и переоткрывает вспомогательное соединение при ошибках, чтобы временные сбои не отравляли последующие вызовы.

### 6.11 Writer / файловый sink ([`Output/EventFileWriter.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Output/EventFileWriter.cs#L16))

- Один JSON-файл на каждое подходящее событие, имя `{yyyyMMdd_HHmmss_fff}_{sanitized-DN}.json`.
- Внутренний lock сериализует `WriteEvent`, чтобы счётчик уникальности имени не входил в гонку и не порождал частично записанные файлы.
- Основа имени обрезается до 180 символов, чтобы не выйти за лимиты пути Windows.
- После каждой успешной записи [`OnFileWritten`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L166) оркестратора инкрементирует счётчик writer'а и обновляет строку статуса.

### 6.12 Консоль / статус ([`Hosting/AppConsole.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/AppConsole.cs#L6))

- Весь лог идёт через `AppConsole.Log` и `AppConsole.WriteException`, чтобы спиннер статуса Spectre.Console не рвался произвольными вызовами `Console.WriteLine`.
- Формат статуса (в `UpdateStatus`): `[grey]{timestamp}[/] notifications: [yellow]{n}[/]  written: [green]{m}[/]`.

### 6.13 Метрики pipeline ([`Pipeline/PipelineMetrics.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/PipelineMetrics.cs#L5))

- Лёгкие in-memory счётчики: события в очереди / обработанные / записанные, ошибки метаданных, ошибки writer'а, ошибки обработки. Логируются периодически через `MaybeLogSnapshot`.

---

## 7. Структуры данных

| Тип | Файл | Назначение |
| --- | --- | --- |
| `Options` | [`Hosting/Options.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/Options.cs#L8) | Распарсенные CLI-опции (Spectre.Console.Cli `CommandSettings`). |
| `ChangeEvent` | [`Models/ChangeEvent.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Models/ChangeEvent.cs#L12) | Сырая запись + распарсенный property-bag, движущиеся через pipeline. |
| `BaselineEntry` | [`Models/BaselineEntry.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Models/BaselineEntry.cs#L10) | Канонический JSON отслеживаемых атрибутов на объект. |
| `NotificationLoopContext` | [`Ldap/LdapNotificationLoopService.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapNotificationLoopService.cs) | Bag входов для одного запуска notification loop (base DN, фабрика, целевая очередь, фильтры игнорирования, callbacks). |
| `MetadataEnrichmentResult` | [`Ldap/MetadataEnricher.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/MetadataEnricher.cs#L13) | Распарсенные записи `msDS-ReplAttributeMetaData`. |
| `BlockingCollection<ChangeEvent>` (incoming) и `BlockingCollection<Dictionary<string,object>>` (outgoing) | [`Pipeline/ChangeProcessingPipeline.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ChangeProcessingPipeline.cs#L25) | Две очереди, связывающие notification, processing и writing. |
| `ConcurrentDictionary<string, BaselineEntry>` | [`Hosting/ChangeMonitorApplication.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L15) | Общее baseline-состояние, ключ — `ObjectKeyBuilder.BuildObjectKey`. |

---

## 8. Сквозной алгоритм

1. **Парсинг CLI.** `Main` ([Hosting/GetChanges.cs:11](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/GetChanges.cs#L11)) передаёт управление Spectre.Console.Cli, который материализует `Options` и вызывает `RunCommand.Execute`.
2. **Спиннер статуса.** `RunCommand.Execute` ([Hosting/GetChanges.cs:20](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/GetChanges.cs#L20)) запускает `AnsiConsole.Status` и вызывает `ChangeMonitorApplication.Run`.
3. **Валидация опций.** `ValidateDomainControllerOptions` ([Hosting/ChangeMonitorApplication.cs:126](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L126)) отвергает несогласованные комбинации `--dc-selection`/`--dc`.
4. **Обнаружение DC + bind.** `LdapConnectionFactory.CreateBoundConnection` ([Ldap/LdapConnectionFactory.cs:50](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapConnectionFactory.cs#L50)) выбирает лучший DC через `DomainControllerSelector` ([Ldap/DomainControllerSelector.cs:28](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/DomainControllerSelector.cs#L28)) и кеширует имя DC под локом.
5. **Определение base DN.** Если опущен, `GetBaseDn` ([Hosting/ChangeMonitorApplication.cs:203](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L203)) читает `defaultNamingContext` из RootDSE.
6. **Загрузка списка игнорирования DN.** Подстрочные фильтры из `--dn-ignore-list`.
7. **Парсинг tracked-attributes.** Пустой список → «писать всё»; непустой → требуется загрузка снимка.
8. **Базовый снимок (опционально).** `BaselineSnapshotLoader.LoadInitialSnapshot` ([Pipeline/BaselineSnapshotLoader.cs:30](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/BaselineSnapshotLoader.cs#L30)) постранично обходит корень поиска и наполняет словарь baseline.
9. **Создание pipeline + writer'а.** Инстанцируются `ChangeProcessingPipeline` и `EventFileWriter`; writer использует `--output-dir` (по умолчанию `.\output`).
10. **Запуск worker'ов.** `pipeline.StartAsync` и `StartWriterLoop` ([Hosting/ChangeMonitorApplication.cs:108](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L108)) запускаются на пуле потоков.
11. **Запуск notification loop.** `LdapNotificationLoopService.RunAsync` ([Ldap/LdapNotificationLoopService.cs:46](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapNotificationLoopService.cs#L46)) запускает persistent search.
12. **Поток одного уведомления.** Внутри `OnPartialResults` ([Ldap/LdapNotificationLoopService.cs:186](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapNotificationLoopService.cs#L186)): применить DN-фильтр → распарсить через `LdapEntryParser` → положить `ChangeEvent` в `Incoming` → запустить `OnNotificationReceived` (счётчик + обновление статуса).
13. **Фильтрация в pipeline.** `ShouldWriteWhenTrackedAttributesChanged` ([Pipeline/ChangeProcessingPipeline.cs:80](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ChangeProcessingPipeline.cs#L80)) сравнивает канонический JSON каждого отслеживаемого атрибута с baseline. На реальном изменении выпускает `_old` / `_new` пары и атомарно обновляет baseline.
14. **Обогащение метаданными (опционально).** `MetadataEnricher.TryLoadMetadata` добавляет `msdsReplAttributeMetaData` в property-bag.
15. **Передача в очередь writer'а.** Property-bag добавляется в `Outgoing`.
16. **Запись JSON-файла.** `EventFileWriter.WriteEvent` ([Output/EventFileWriter.cs:29](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Output/EventFileWriter.cs#L29)) формирует уникальный путь и сериализует через `Newtonsoft.Json` (с отступами, UTF-8 без BOM).
17. **Обновление счётчика записи.** `OnFileWritten` ([Hosting/ChangeMonitorApplication.cs:166](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L166)) инкрементирует `_eventsWrittenCount` и обновляет строку статуса.
18. **Переподключение при временных ошибках.** Когда `IsRecoverableNotificationException` ([Ldap/LdapNotificationLoopService.cs:272](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapNotificationLoopService.cs#L272)) возвращает true, цикл вызывает `OnBeforeReconnect` (сбрасывает кэш DC), спит `CalculateReconnectDelay(attempt)` (с верхней границей 60 с и jitter) и повторяет.
19. **Сигнал останова.** `MonitoringLifecycleService.WaitForStopSignal` ([Hosting/MonitoringLifecycleService.cs:24](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/MonitoringLifecycleService.cs#L24)) разблокируется по ENTER или CTRL+C.
20. **Кооперативное завершение.** `RequestStop` отменяет токен; оркестратор ждёт до 5 с notification loop, затем закрывает очередь `Incoming`, затем ждёт до 5 с задачи worker'а и writer'а. Ограниченные ожидания гарантируют выход процесса.

---

## 9. Сборка, запуск, публикация

- **Restore:** `& "$env:USERPROFILE\.nuget\nuget.exe" restore GetChanges.sln`
- **Сборка (Release):** `msbuild GetChanges.sln /p:Configuration=Release /v:minimal`
- **Артефакт:** `GCNet\bin\Release\GCNet.exe` (Costura.Fody встраивает зависимости в один исполняемый файл; см. `GCNet/FodyWeavers.xml`).
- **Подмодуль:** `SharpHoundCommon/` подключается через project reference как `net472`. Инициализация — `git submodule update --init --recursive`.

---

## 10. Заметки по безопасности

- **Чувствительный вывод.** JSON-файлы событий буквально воспроизводят данные каталога (включая ACE, SID, историю атрибутов). Считайте каталог вывода чувствительным; ротируйте / ограничивайте доступ.
- **Отключённая проверка сертификата.** `LdapConnectionFactory` коротко замыкает `VerifyServerCertificate`, чтобы разрешить внутреннее AD-лабораторное использование. Замените реальной валидацией перед любым внешним развёртыванием — см. inline-комментарий `SECURITY`.
- **Привилегии учётной записи.** Связанная учётка читает всё, что разрешено настроенным `--base-dn`; применяйте принцип наименьших привилегий.

---

## 11. Будущие улучшения / идеи

- Ограничить in-process очереди, чтобы медленный диск не наращивал память процесса безгранично.
- Распараллелить health-проверки DC при `auto`-выборе.
- Перевести логирование с `AppConsole` на `Microsoft.Extensions.Logging`.
- Выставить метрики pipeline через `EventCounters` / ETW.
- Опциональное per-attribute tombstone-отслеживание.

---

## 12. Связанные документы

- [README.md](README.md) — англоязычная версия (является источником истины; этот файл — её перевод).
- [AGENTS.md](AGENTS.md) — стиль кода, команды сборки, файлы, обязательные к обновлению, для этой ветки.
- `SharpHoundCommon/README.md` — обзор подмодуля и тесты.
