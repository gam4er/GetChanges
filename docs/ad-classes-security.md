# Классы Active Directory: безопасность и поверхность атаки

> Справочник по 75 классам схемы AD, наблюдаемым в реальных корпоративных доменах
> (источник перечня — [classSchemaObjectGUID.csv](../classSchemaObjectGUID.csv)).
> Документ предназначен для blue-team / IR / архитекторов AD: даёт назначение каждого
> класса, его роль в моделях привилегий и типовые пути атаки на основе **техник**
> (без привязки к конкретным offensive-инструментам).

## Зачем это нужно

GCNet перехватывает изменения в AD через persistent search. Чтобы корректно
интерпретировать `objectClass` в потоке событий и расставлять приоритеты
расследования, нужно понимать:

- какую функциональную нагрузку несёт каждый класс;
- как он привязан к моделям привилегий (Tier 0 / 1 / 2);
- какие операции над объектом этого класса дают атакующему путь к повышению
  привилегий или контролю над инфраструктурой;
- какие изменения должны вызывать алёрт высокой критичности.

## Методология и оговорки

- **Источник определений** — официальная страница MS Learn по схеме AD
  (`https://learn.microsoft.com/en-us/windows/win32/adschema/`). Каждый GUID
  в сводной таблице ведёт на соответствующую страницу схемы.
- **Tier** — отнесение к [Microsoft tiered administration model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model):
  - **T0** — компрометация ⇒ контроль над лесом / доменом / KDC.
  - **T1** — серверы и серверные приложения; компрометация даёт массовый доступ к данным.
  - **T2** — рабочие станции и пользовательские объекты.
- **Critical** — суммарная оценка того, насколько изменение объекта данного
  класса должно эскалироваться в SOC: **Critical / High / Medium / Low**.
  Учитывает потенциальный impact, а не вероятность.
- **schemaIDGUID ≠ rightsGuid.** GUID в сводной таблице — это идентификатор
  _класса схемы_, а не extended right; не путать с GUID-ами в SDDL вида
  `(OA;;CR;<rightsGuid>;;<sid>)`.
- **Live-данные не цитируем.** В документе используются только дефолтные
  Default Security Descriptors из MS Learn и обезличенные примеры
  (`contoso.local`, `WS-XXXX$`, `S-1-5-21-XXXX-XXXX-XXXX-<RID>`).
- **Несколько классов отсутствуют на MS Learn** — это, как правило, расширения
  схемы от Exchange / SCCM / IEEE-Wi-Fi-policy. Для них дана ссылка на
  [индекс схемы](https://learn.microsoft.com/en-us/windows/win32/adschema/active-directory-schema)
  и пояснение в сноске.

## Легенда колонок

| Колонка           | Значение                                                                                       |
| ----------------- | ---------------------------------------------------------------------------------------------- |
| **Class**         | `lDAPDisplayName` объекта класса (как приходит в `objectClass`).                               |
| **classSchemaCN** | `cn` записи в `CN=Schema,CN=Configuration,DC=…`.                                               |
| **schemaIDGUID**  | GUID класса. Кликабельная ссылка ведёт на MS Learn.                                            |
| **Tier**          | T0 / T1 / T2 (см. выше). `—` для абстрактных/структурных.                                      |
| **Critical**      | Critical / High / Medium / Low.                                                                |
| **Назначение**    | 1-строчное описание. Для классов с подробным разделом ниже — имя в первой колонке кликабельно. |

---

## Сводная таблица (75 классов)

Отсортировано по убыванию Critical, внутри — по имени класса.

| Class                                                                                             | classSchemaCN                        | schemaIDGUID                                                                                               | Tier  | Critical | Назначение                                                                              |
| ------------------------------------------------------------------------------------------------- | ------------------------------------ | ---------------------------------------------------------------------------------------------------------- | ----- | -------- | --------------------------------------------------------------------------------------- |
| [`domainDNS`](#domaindns)                                                                         | Domain-DNS                           | [19195a5b-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-domaindns)                         | T0    | Critical | Корень домена; владеет `nTSecurityDescriptor` всего NC и правами DCSync.                |
| [`domain`](#domain)                                                                               | Domain                               | [19195a5a-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-domain)                            | T0    | Critical | Базовый класс домена; родитель `domainDNS`.                                             |
| [`samServer`](#samserver)                                                                         | Sam-Server                           | [bf967aad-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-samserver)                         | T0    | Critical | `CN=Server,CN=System` — настройки SAM, расширенное право `SAM-Enumerate-Entire-Domain`. |
| [`rIDManager`](#ridmanager)                                                                       | RID-Manager                          | [6617188d-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-ridmanager)                        | T0    | Critical | Раздаёт RID-пулы DC; контроль ⇒ возможность фабриковать SID.                            |
| `rIDSet`                                                                                          | RID-Set                              | [7bfdcb89-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-ridset)                            | T0    | Critical | Пер-DC RID-пул; см. раздел [`rIDManager`](#ridmanager).                                 |
| `infrastructureUpdate`                                                                            | Infrastructure-Update                | [2df90d89-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-infrastructureupdate)              | T0    | Critical | Объект FSMO Infrastructure Master; FSMO-владение = расширенные права.                   |
| [`trustedDomain`](#trusteddomain)                                                                 | Trusted-Domain                       | [bf967ab8-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-trusteddomain)                     | T0    | Critical | Объект доверительных отношений; контроль ⇒ Golden/Trust-ticket, SID-history injection.  |
| [`domainPolicy`](#domainpolicy)                                                                   | Domain-Policy                        | [bf967a99-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-domainpolicy)                      | T0    | Critical | Default Domain Policy attachment-point; legacy, но meta-флаги влияют на Kerberos.       |
| [`nTFRSReplicaSet`](#ntfrsreplicaset)                                                             | NTFRS-Replica-Set                    | [5245803a-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-ntfrsreplicaset)                   | T0    | Critical | Legacy SYSVOL-репликация (FRS); до миграции на DFSR — контроль = SYSVOL tampering.      |
| `nTFRSSettings`                                                                                   | NTFRS-Settings                       | [f780acc2-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-ntfrssettings)                     | T0    | Critical | Контейнер настроек FRS; см. [`nTFRSReplicaSet`](#ntfrsreplicaset).                      |
| [`groupPolicyContainer`](#grouppolicycontainer)                                                   | Group-Policy-Container               | [f30e3bc2-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-grouppolicycontainer)              | T0    | Critical | AD-часть GPO; запись в `gPCFileSysPath` или GPC ⇒ массовая RCE на linked-SOM.           |
| [`msDFSR-GlobalSettings`](#msdfsr-семейство)                                                      | ms-DFSR-GlobalSettings               | [7b35dbad-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-globalsettings)             | T0    | Critical | Корневые настройки DFSR; контроль над репликацией SYSVOL.                               |
| `msDFSR-Topology`                                                                                 | ms-DFSR-Topology                     | [04828aa9-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-topology)                   | T0    | Critical | Топология DFSR; см. [DFSR-семейство](#msdfsr-семейство).                                |
| `msDFSR-ReplicationGroup`                                                                         | ms-DFSR-ReplicationGroup             | [1c332fe0-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-replicationgroup)           | T0    | Critical | Группа репликации (включая Domain System Volume).                                       |
| `msDFSR-Content`                                                                                  | ms-DFSR-Content                      | [64759b35-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-content)                    | T0    | Critical | Контейнер контент-наборов RG.                                                           |
| `msDFSR-ContentSet`                                                                               | ms-DFSR-ContentSet                   | [4937f40d-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-contentset)                 | T0    | Critical | Описание реплицируемой папки (для SYSVOL — путь к SYSVOL\domain).                       |
| `msDFSR-Member`                                                                                   | ms-DFSR-Member                       | [4229c897-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-member)                     | T0    | Critical | DC-член RG; ссылается на `computer` DC.                                                 |
| `msDFSR-Subscriber`                                                                               | ms-DFSR-Subscriber                   | [e11505d7-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-subscriber)                 | T0    | High     | Подписчик content-set'а на конкретном DC.                                               |
| `msDFSR-Subscription`                                                                             | ms-DFSR-Subscription                 | [67212414-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-subscription)               | T0    | High     | Локальная подписка (per-set, per-DC).                                                   |
| `msDFSR-LocalSettings`                                                                            | ms-DFSR-LocalSettings                | [fa85c591-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-localsettings)              | T0    | High     | Per-DC контейнер DFSR-настроек (под `computer` DC).                                     |
| `msDFSR-Connection`                                                                               | ms-DFSR-Connection                   | [e58f972e-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msdfsr-connection)                 | T0    | High     | Описание connection между DFSR-членами.                                                 |
| [`dnsZone`](#dnszone--dnsnode)                                                                    | Dns-Zone                             | [e0fa1e8b-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-dnszone)                           | T0/T1 | High     | AD-integrated DNS-зона; контроль ⇒ ADIDNS spoofing, NTLM-relay на DC.                   |
| `dnsNode`                                                                                         | Dns-Node                             | [e0fa1e8c-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-dnsnode)                           | T0/T1 | High     | Запись внутри `dnsZone`. См. [DNS](#dnszone--dnsnode).                                  |
| `dnsZoneScope`                                                                                    | Dns-Zone-Scope                       | [696f8a61-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-dnszonescope)                      | T0/T1 | Medium   | Split-scope DNS (Windows Server 2016+).                                                 |
| `dnsZoneScopeContainer`                                                                           | Dns-Zone-Scope-Container             | [f2699093-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-dnszonescopecontainer)             | T0/T1 | Medium   | Контейнер для `dnsZoneScope`.                                                           |
| [`user`](#user--person--organizationalperson)                                                     | User                                 | [bf967aba-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-user)                              | T0–T2 | Critical | Учётная запись; включает `krbtgt`, DA, EA, service-accounts.                            |
| `person`                                                                                          | Person                               | [bf967aa7-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-person)                            | —     | High     | Абстрактный родитель `user`/`organizationalPerson`.                                     |
| `organizationalPerson`                                                                            | Organizational-Person                | [bf967aa4-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-organizationalperson)              | —     | High     | Абстрактный родитель `user`. Изменение `Person`-атрибутов через этот класс.             |
| [`group`](#group)                                                                                 | Group                                | [bf967a9c-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-group)                             | T0–T2 | Critical | Группа безопасности/рассылки; членство в `Domain Admins` и т. п.                        |
| [`computer`](#computer)                                                                           | Computer                             | [bf967a86-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-computer)                          | T0–T2 | High     | Машинная учётка; включает DC. RBCD, S4U, LAPS, BitLocker recovery.                      |
| [`msDS-GroupManagedServiceAccount`](#msds-groupmanagedserviceaccount--msds-managedserviceaccount) | ms-DS-Group-Managed-Service-Account  | [7b8b558a-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-groupmanagedserviceaccount)   | T0/T1 | High     | gMSA; чтение `msDS-ManagedPassword` ⇒ компрометация сервиса.                            |
| `msDS-ManagedServiceAccount`                                                                      | ms-DS-Managed-Service-Account        | [ce206244-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msds-managedserviceaccount)        | T1    | High     | sMSA (single-host MSA).                                                                 |
| [`foreignSecurityPrincipal`](#foreignsecurityprincipal)                                           | Foreign-Security-Principal           | [89e31c12-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-foreignsecurityprincipal)          | T0–T2 | High     | Заглушка под внешний SID (cross-forest, well-known). SID-history abuse.                 |
| [`msWMI-Som`](#mswmi-som)                                                                         | ms-WMI-Som                           | [ab857078-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-mswmi-som)                         | T1/T2 | High     | WMI-фильтр GPO; влияет, к каким машинам применяется политика.                           |
| [`classStore`](#classstore--packageregistration--intellimirrorscp)                                | Class-Store                          | [bf967a84-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-classstore)                        | T1/T2 | High     | Контейнер для GPSI (software install via GPO).                                          |
| `packageRegistration`                                                                             | Package-Registration                 | [bf967aa6-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-packageregistration)               | T1/T2 | High     | Зарегистрированный MSI/ZAP-пакет в GPSI. SYSTEM-RCE на target.                          |
| `intellimirrorSCP`                                                                                | Intellimirror-SCP                    | [07383085-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-intellimirrorscp)                  | T1/T2 | High     | SCP старого IntelliMirror-сервиса деплоя.                                               |
| [`mSSMSManagementPoint`](#mssms-семейство-sccm--mecm)                                             | MS-SMS-Management-Point              | d92f3bd1-… [†](#sccm-note)                                                                                 | T1    | High     | SCCM Management Point SCP; компрометация SCCM = массовая RCE.                           |
| `mSSMSSite`                                                                                       | MS-SMS-Site                          | b409d5ef-… [†](#sccm-note)                                                                                 | T1    | High     | SCCM Site SCP.                                                                          |
| `mSSMSRoamingBoundaryRange`                                                                       | MS-SMS-Roaming-Boundary-Range        | f5f05029-… [†](#sccm-note)                                                                                 | T1    | Medium   | Boundary-ranges клиентов SCCM.                                                          |
| [`organizationalUnit`](#organizationalunit--container--builtindomain)                             | Organizational-Unit                  | [bf967aa5-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-organizationalunit)                | T0–T2 | High     | Контейнер с собственным ACL; делегирование, gpLink.                                     |
| `container`                                                                                       | Container                            | [bf967a8b-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-container)                         | T0–T2 | High     | Системный контейнер (включая `CN=AdminSDHolder`, `CN=Users`).                           |
| `builtinDomain`                                                                                   | Builtin-Domain                       | [bf967a81-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-builtindomain)                     | T0    | High     | `CN=Builtin` — Administrators, Account Operators и т.п.                                 |
| [`serviceConnectionPoint`](#serviceconnectionpoint--serviceadministrationpoint)                   | Service-Connection-Point             | [28630ec1-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-serviceconnectionpoint)            | T1/T2 | Medium   | Публикация сервиса в AD. Rogue SCP ⇒ coerce auth, NTLM relay.                           |
| `serviceAdministrationPoint`                                                                      | Service-Administration-Point         | [b7b13123-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-serviceadministrationpoint)        | T1/T2 | Medium   | SCP для административных интерфейсов.                                                   |
| [`rRASAdministrationConnectionPoint`](#rrasadministrationconnectionpoint)                         | RRAS-Administration-Connection-Point | [2a39c5be-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-rrasadministrationconnectionpoint) | T1    | Medium   | Публикация RRAS/VPN-сервера; периметр.                                                  |
| [`ipsecBase`](#ipsec-классы)                                                                      | Ipsec-Base                           | [b40ff825-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-ipsecbase)                         | T1    | Medium   | Базовый класс IPSec policy.                                                             |
| `ipsecNegotiationPolicy`                                                                          | Ipsec-Negotiation-Policy             | [b40ff827-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-ipsecnegotiationpolicy)            | T1    | Medium   | Политика IPSec-переговоров (legacy).                                                    |
| [`ms-net-ieee-80211-GroupPolicy`](#wi-fi-group-policy-классы)                                     | ms-net-ieee-80211-GroupPolicy        | [1cb81863-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-ms-net-ieee-80211-grouppolicy)     | T2    | Medium   | 802.11 (Wi-Fi) GP; PSK/EAP-конфиги.                                                     |
| `msieee80211-Policy`                                                                              | ms-ieee-80211-Policy                 | 7b9a2d92-… [†](#ieee-note)                                                                                 | T2    | Medium   | Старый формат 802.11 policy.                                                            |
| [`msDS-DeviceContainer`](#msds-devicecontainer)                                                   | ms-DS-Device-Container               | 7c9e8c58-… [†](#device-container-note)                                                                     | T1/T2 | Medium   | Контейнер `msDS-Device` объектов (Hybrid Azure AD Join).                                |
| `msExchSystemObjectsContainer`                                                                    | ms-Exch-System-Objects-Container     | [0bffa04c-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msexchsystemobjectscontainer)      | T1    | Medium   | Контейнер system-объектов Exchange; исторически Exchange Windows Permissions.           |
| `msExchDynamicDistributionList`                                                                   | ms-Exch-Dynamic-Distribution-List    | 018849b0-… [†](#exchange-note)                                                                             | T2    | Low      | Динамическая DL Exchange.                                                               |
| `dfsConfiguration`                                                                                | Dfs-Configuration                    | [8447f9f2-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-dfsconfiguration)                  | T1    | Medium   | DFS-N namespace root в AD; редирект на ложные шары.                                     |
| `fTDfs`                                                                                           | FT-Dfs                               | [8447f9f3-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-ftdfs)                             | T1    | Medium   | Fault-tolerant DFS root.                                                                |
| [`ms-srvShareMapping`](#ms-srvsharemapping)                                                       | ms-SrvShareMapping                   | c356f65b-… [†](#share-mapping-note)                                                                        | T2    | Medium   | Per-user маппинги шар (Folder Redirection / Roaming).                                   |
| `volume`                                                                                          | Volume                               | [bf967abb-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-volume)                            | T2    | Medium   | Опубликованная шара.                                                                    |
| `printQueue`                                                                                      | Print-Queue                          | [bf967aa8-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-printqueue)                        | T1/T2 | Medium   | Опубликованный принтер; контекст PrintNightmare.                                        |
| `mSMQConfiguration`                                                                               | MSMQ-Configuration                   | [9a0dc344-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msmqconfiguration)                 | T1    | Medium   | MSMQ host-config; legacy CVE (QueueJumper и др.).                                       |
| `mSMQQueue`                                                                                       | MSMQ-Queue                           | [9a0dc343-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-msmqqueue)                         | T1    | Medium   | Публичная очередь MSMQ.                                                                 |
| `securityObject`                                                                                  | Security-Object                      | [bf967aaf-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-securityobject)                    | —     | Medium   | Базовый класс для объектов с `nTSecurityDescriptor`.                                    |
| `connectionPoint`                                                                                 | Connection-Point                     | [5cb41ecf-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-connectionpoint)                   | —     | Low      | Абстрактный родитель SCP-классов.                                                       |
| `applicationSettings`                                                                             | Application-Settings                 | [f780acc1-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-applicationsettings)               | T2    | Low      | Настройки приложения, опубликованные в AD.                                              |
| `categoryRegistration`                                                                            | Category-Registration                | [7d6c0e9d-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-categoryregistration)              | —     | Low      | Регистрация COM-категорий.                                                              |
| `serviceClass`                                                                                    | Service-Class                        | [bf967ab1-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-serviceclass)                      | —     | Low      | Описание service class (legacy).                                                        |
| `serviceInstance`                                                                                 | Service-Instance                     | [bf967ab2-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-serviceinstance)                   | —     | Low      | Конкретный экземпляр сервиса (legacy).                                                  |
| `rpcContainer`                                                                                    | Rpc-Container                        | [80212842-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-rpccontainer)                      | T1    | Low      | Контейнер для RPC SCP.                                                                  |
| `contact`                                                                                         | Contact                              | [5cb41ed0-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-contact)                           | T2    | Low      | Контакт без login (mail, phone).                                                        |
| `top`                                                                                             | Top                                  | [bf967ab7-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-top)                               | —     | Low      | Корневой класс схемы.                                                                   |
| `leaf`                                                                                            | Leaf                                 | [bf967a9e-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-leaf)                              | —     | Low      | Абстрактный leaf-класс.                                                                 |
| `lostAndFound`                                                                                    | Lost-And-Found                       | [52ab8671-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-lostandfound)                      | —     | Low      | Контейнер «осиротевших» объектов после конфликтов репликации.                           |
| `fileLinkTracking`                                                                                | File-Link-Tracking                   | [dd712229-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-filelinktracking)                  | T2    | Low      | Distributed Link Tracking.                                                              |
| `linkTrackObjectMoveTable`                                                                        | Link-Track-Object-Move-Table         | [ddac0cf5-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-linktrackobjectmovetable)          | T2    | Low      | Таблица DLT.                                                                            |
| `linkTrackOMTEntry`                                                                               | Link-Track-OMT-Entry                 | [ddac0cf7-…](https://learn.microsoft.com/en-us/windows/win32/adschema/c-linktrackomtentry)                 | T2    | Low      | Запись DLT.                                                                             |
| `msImaging-PSPs`                                                                                  | ms-Imaging-PSPs                      | a0ed2ac1-… [†](#imaging-note)                                                                              | T2    | Low      | PSP-конфиги для сканеров (WIA).                                                         |

**Сноски к нестандартным URL (не имеют публичной страницы на MS Learn adschema):**

- <a id="sccm-note"></a>† SCCM/MECM-расширения (`mSSMS*`) — вендорная схема ConfigMgr; описание см. в
  [ConfigMgr documentation: Schema extensions](https://learn.microsoft.com/en-us/mem/configmgr/core/plan-design/network/extend-the-active-directory-schema).
- <a id="ieee-note"></a>† Старая 802.11 policy (`msieee80211-Policy`) была заменена на `ms-net-ieee-80211-GroupPolicy`.
- <a id="device-container-note"></a>† `msDS-DeviceContainer` упоминается в документации [Hybrid Azure AD Join](https://learn.microsoft.com/en-us/entra/identity/devices/concept-hybrid-join), отдельной adschema-страницы нет.
- <a id="exchange-note"></a>† Exchange schema (`msExch*`) описана в документации Exchange, не в adschema-индексе.
- <a id="share-mapping-note"></a>† `ms-srvShareMapping` — расширение Folder Redirection; см. ldapDisplayName в `CN=Schema` живого леса.
- <a id="imaging-note"></a>† `msImaging-PSPs` — расширение для Windows Image Acquisition.

---

## domainDNS

**Назначение.** Корневой объект NC домена (`DC=contoso,DC=local`). Хранит
доменные политики паролей/Kerberos, ссылки `gPLink` на `groupPolicyContainer`
и владеет `nTSecurityDescriptor`, через который раздаются права на NC,
включая extended rights `DS-Replication-Get-Changes` и
`DS-Replication-Get-Changes-All` (DCSync).

**Ключевые атрибуты.**

- `nTSecurityDescriptor` — ACL всего NC; цель №1 для подмены.
- `gPLink`, `gPOptions` — привязка GPO к домену.
- `msDS-Behavior-Version`, `msDS-AllowedDNSSuffixes`, `lockoutDuration`,
  `maxPwdAge`, `minPwdLength`, `pwdProperties`, `lockoutThreshold` —
  доменные политики.
- `wellKnownObjects` — well-known контейнеры (Users, Computers, AdminSDHolder).
- `objectSid` домена + `rIDManagerReference` (на `rIDManager`).

**Attacker view.**

- WriteDACL на NC (даже временный) ⇒ выдать `DS-Replication-Get-Changes-All`
  любому SID ⇒ DCSync ⇒ извлечение хеша `krbtgt` ⇒ Golden Ticket.
- WriteProperty на `gPLink` ⇒ привязка вредоносного GPO к домену ⇒
  массовая RCE на всех клиентах.
- Изменение `pwdProperties`/`maxPwdAge` ⇒ ослабление парольной политики
  на этапе persistence.

**Detection / GCNet.**

- Любая модификация `nTSecurityDescriptor` или `gPLink` объекта класса
  `domainDNS` — Critical-алёрт.
- Изменения `pwdProperties`, `lockoutThreshold`, `msDS-Behavior-Version`
  должны проходить ревью CAB.

---

## domain

**Назначение.** Базовый класс, родитель `domainDNS`. На уровне instance
обычно не встречается отдельно от `domainDNS`; в живом лесу один объект
`CN=…` имеет `objectClass=top;domain;domainDNS`. Отдельная строка в потоке
изменений с classOnly `domain` маловероятна — но `objectClass` **массива**
содержит этот класс наравне с `domainDNS`.

**Attacker view / Detection.** Те же векторы, что у [`domainDNS`](#domaindns).

---

## samServer

**Назначение.** `CN=Server,CN=System,DC=…`. Объект с extended rights
`Domain-Administer-Server` и `SAM-Enumerate-Entire-Domain` (rights GUID,
не атрибут). Default Security Descriptor по схеме —
`D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;RPLCLORC;;;AU)(A;;RPLCLORC;;;RU)`.

**Attacker view.**

- Делегирование `Domain-Administer-Server` нестандартному принципалу — путь
  к контролю над SAM-операциями и созданию учёток с обходом обычных ACL OU.
- `SAM-Enumerate-Entire-Domain`, выданное низкопривилегированному
  принципалу, превращает его в эффективного аудитора — но ничего не пишет;
  важно для discovery-фазы.

**Detection / GCNet.**

- Изменение `nTSecurityDescriptor` на CN=Server,CN=System — Critical.
- Любые ACE с `OBJECT_TYPE` = `0ab4bc02-…` (`Domain-Administer-Server`)
  или `91d67418-…` (`SAM-Enumerate-Entire-Domain`) на нестандартных
  принципалах — High.

---

## rIDManager

**Назначение.** `CN=RID Manager$,CN=System` — FSMO RID-master. Раздаёт
RID-пулы DC-ам через атрибут `rIDAvailablePool` (64-битный счётчик).
Связанный класс `rIDSet` (под каждым `computer` DC) хранит выделенный
этому DC пул.

**Attacker view.**

- WriteProperty на `rIDAvailablePool` ⇒ возможность повторно выдать уже
  использованные RID или вытолкнуть пул в произвольное значение ⇒ создание
  объектов с поддельными SID, конфликты с привилегированными аккаунтами.
- Контроль над `rIDSetReferences` на DC ⇒ возможность сбить генерацию
  SID на конкретном DC.

**Detection / GCNet.**

- Прямые изменения `rIDAvailablePool` вне FSMO-операций — Critical.
- `rIDNextRID` или `rIDPreviousAllocationPool` смены — нормальный
  trafiс при работе DC; alert только на скачки.

---

## trustedDomain

**Назначение.** Объект в `CN=System,DC=…`, описывающий доверительные
отношения с внешним доменом/лесом. Содержит ключи доверия (`trustAuthIncoming`,
`trustAuthOutgoing` — TDO secret), флаги, тип доверия, SID партнёра,
`msDS-TrustForestTrustInfo` (forest-trust info, FTInfo).

**Ключевые атрибуты.**

- `trustAuthIncoming`, `trustAuthOutgoing` — secrets (TDO trust keys).
  Из них выводится Inter-Realm TGT key.
- `trustAttributes` — флаги: `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN` (SID-filter),
  `TRUST_ATTRIBUTE_FOREST_TRANSITIVE`, `TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL`.
- `trustDirection`, `trustType`, `flatName`, `securityIdentifier`.
- `msDS-SupportedEncryptionTypes`.

**Attacker view.**

- Контроль над `trustAuthIncoming/Outgoing` ⇒ Inter-Realm Forge (Trust Ticket)
  ⇒ возможность выпускать TGT в любой домен trust-цепочки.
- Сброс `TRUST_ATTRIBUTE_QUARANTINED_DOMAIN` (отключение SID-filtering) ⇒
  возможность SID-history injection из менее доверенного домена.
- Создание нового `trustedDomain` с подконтрольным внешним лесом ⇒
  cross-forest TGT forge.
- `msDS-TrustForestTrustInfo` модификация ⇒ добавление поддельных TLN/SID
  записей в forest-trust scope.

**Detection / GCNet.**

- Любое создание/удаление `trustedDomain` — Critical.
- Изменение `trustAttributes` (особенно сброс quarantine-битов) — Critical.
- Изменения `trustAuth*` — Critical (даже легитимные password rolling
  идут с известной периодичностью и должны быть skedjul'ом).

---

## domainPolicy

**Назначение.** Legacy-класс «Default Domain Policy attachment-point»
(до GPO в современном смысле). В современных доменах объект сам по себе
не управляет политикой паролей (это атрибуты `domainDNS`), но класс
сохраняется для совместимости. Часто содержит `eFSPolicy`, `qualityOfService`.

**Attacker view.**

- Малое практическое применение в современных доменах, но любая запись
  в этот объект подозрительна (исторический backdoor-вектор для
  «незаметных» изменений политики через legacy-attribute-set).

**Detection.** Любое изменение `domainPolicy` — High; в большинстве
доменов объект статичен.

---

## nTFRSReplicaSet

**Назначение.** Legacy-репликация SYSVOL через NTFRS (до миграции на DFSR).
В современных доменах SYSVOL реплицируется DFSR, и объекты NTFRS либо
отсутствуют, либо «спящие». Если домен **не** мигрирован (`dfsrmig /getmigrationstate`),
NTFRS-объекты — критичная поверхность.

**Attacker view.**

- Контроль над `nTFRSReplicaSet` пре-миграции ⇒ возможность подмены
  SYSVOL-контента на одном DC ⇒ распространение через FRS ⇒
  GPO/scripts injection домен-wide ⇒ массовая RCE.

**Detection / GCNet.**

- В DFSR-only доменах любая активность на `nTFRSReplicaSet` /
  `nTFRSSettings` — High (потенциальный downgrade-attempt).
- Проверка миграции SYSVOL — отдельная регулярная задача.

---

## groupPolicyContainer

**Назначение.** AD-часть GPO. Файловая часть лежит в
`\\<domain>\SYSVOL\<domain>\Policies\{GUID}` и реплицируется DFSR/NTFRS;
AD-часть содержит `gPCFileSysPath`, `gPCFunctionalityVersion`,
`gPCMachineExtensionNames`, `gPCUserExtensionNames`, `gPCWQLFilter`
(ссылка на `msWMI-Som`).

**Атаки на GPO разделены на два слоя:**

1. **AD-слой:** WriteProperty на GPC.
2. **SYSVOL-слой:** Write на `gPCFileSysPath` файлы (`GptTmpl.inf`,
   `Registry.pol`, `Scripts.ini`, `ScheduledTasks.xml`, MSI install).

**Attacker view.**

- WriteProperty `gPCFileSysPath` ⇒ переадресация на подконтрольную шару ⇒
  любая `gPLink`-привязка ⇒ RCE на всех target-машинах.
- Write в SYSVOL-часть GPO (если есть права на NTFS) ⇒ GPO injection
  через `Scripts.ini`/`ScheduledTasks.xml` ⇒ SYSTEM/User-context RCE
  на target.
- Создание нового GPO + linking к OU с DC (`OU=Domain Controllers`) ⇒
  компрометация DC.
- Изменение `gPCWQLFilter` ⇒ перенаправление таргетинга на/с конкретных
  машин (через [`msWMI-Som`](#mswmi-som)).
- Modify `nTSecurityDescriptor` GPO ⇒ скрытие GPO от
  `gpresult`/инвентаризации (через `Apply-Group-Policy` extended right).

**Detection / GCNet.**

- Любое создание/удаление `groupPolicyContainer` — High; должно
  коррелироваться с change-request.
- Изменения `gPCFileSysPath`, `gPCMachineExtensionNames` (новые CSE) —
  Critical.
- Изменение `nTSecurityDescriptor` GPC — High (особенно ACE на
  `Apply-Group-Policy` rightsGuid).
- Параллельный мониторинг файловой части SYSVOL обязателен.

---

## msDFSR-семейство

**Назначение.** Distributed File System Replication — современный механизм
репликации SYSVOL и произвольных RG. Иерархия:

```
CN=DFSR-GlobalSettings,CN=System,DC=…
└── ms-DFSR-ReplicationGroup (например, "Domain System Volume")
    ├── ms-DFSR-Content
    │   └── ms-DFSR-ContentSet (≈ replicated folder)
    └── ms-DFSR-Topology
        └── ms-DFSR-Member (per-DC)
            └── ms-DFSR-Connection (incoming/outgoing edges)

CN=DFSR-LocalSettings,CN=<DC>,…  (под каждым `computer`-объектом DC)
└── ms-DFSR-Subscriber
    └── ms-DFSR-Subscription
```

**Attacker view.**

- `msDFSR-ContentSet.msDFSR-RootPath` и `msDFSR-StagingPath` указывают
  локальный путь — подмена путей ⇒ DC начнёт реплицировать произвольные
  каталоги ⇒ возможность опубликовать вредоносный SYSVOL-контент.
- Удаление/реконфигурация `msDFSR-Connection` ⇒ split-brain в
  Domain System Volume ⇒ inconsistent SYSVOL ⇒ окно для распространения
  «локально-верного» вредоносного GPO с одного DC.
- Контроль над `msDFSR-Member.msDFSR-ComputerReference` ⇒ переключение
  репликации на rogue-машину под видом DC.

**Detection / GCNet.**

- Любые модификации `msDFSR-ContentSet`/`msDFSR-Subscription` для
  RG `Domain System Volume` — Critical.
- Создание `msDFSR-Connection` вне DC-baseline-топологии — High.

---

## dnsZone / dnsNode

**Назначение.** AD-integrated DNS. `dnsZone` — зона (например, `contoso.local`),
`dnsNode` — отдельная запись (`A`, `SRV`, `CNAME`). Хранятся в
`DC=contoso,DC=local,CN=MicrosoftDNS,DC=DomainDnsZones,…` или в NC `DC=ForestDnsZones`.
Default Security Descriptor `dnsZone` (Windows Server 2003+):
`D:(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;DA)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;ED)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;SY)(A;;CC;;;AU)(A;;RPLCLORC;;;WD)(A;;RPWPCRCCDCLCLORCWOWDSDDTSW;;;CO)`
— **`Authenticated Users` имеют `CreateChild`**, что и позволяет ADIDNS-атаки.

**Attacker view (ADIDNS spoofing).**

- Любой аутентифицированный пользователь может создать `dnsNode` (например,
  `wpad`, `webproxy`, отсутствующий hostname в `_ldap._tcp.`-структуре) ⇒
  отравление имён ⇒ NTLM relay ⇒ компрометация серверов / DC.
- Подмена SRV-записей `_kerberos._tcp.dc._msdcs` ⇒ перенаправление
  Kerberos-аутентификации на rogue-KDC.
- Создание wildcard `*` в зоне ⇒ перехват любых неразрешённых имён.
- WriteProperty `dnsRecord` существующего `dnsNode` ⇒ overwrite legitimate
  записей (нужна выше привилегия — ACL обычно ограничен `CreatorOwner`).
- Контроль над `dnsZone.nTSecurityDescriptor` ⇒ тотальный контроль зоны.

**Detection / GCNet.**

- Создание `dnsNode` под не-DNS-серверной учёткой — High.
- Записи с именами `wpad`, `isatap`, `webproxy`, `*`, `_ldap`, `_kerberos`,
  `_gc` — Critical (особенно если автор не DC-computer).
- Изменение `nTSecurityDescriptor` `dnsZone` — Critical.

---

## user / person / organizationalPerson

**Назначение.** `user` наследует от `organizationalPerson`, который
наследует от `person` → `top`. В живом потоке `objectClass` user-объекта
содержит все три. Включает: обычных пользователей, привилегированные
учётки (DA/EA/Schema Admins), `krbtgt`, service-accounts (без UAC-флагов
MSA/gMSA), Read-Only DC `krbtgt_<XXXXX>`.

**Ключевые атрибуты безопасности.**

- `userAccountControl` (UAC): флаги `TRUSTED_FOR_DELEGATION` (unconstrained),
  `TRUSTED_TO_AUTH_FOR_DELEGATION` (constrained, S4U2Self), `DONT_REQUIRE_PREAUTH`
  (AS-REP roastable), `PASSWD_NOTREQD`, `DONT_EXPIRE_PASSWORD`.
- `servicePrincipalName` (SPN) — наличие у user-account ⇒ Kerberoastable.
- `msDS-AllowedToActOnBehalfOfOtherIdentity` (RBCD acceptor).
- `msDS-AllowedToDelegateTo` (constrained delegation targets).
- `msDS-KeyCredentialLink` — Shadow Credentials primitive (WHfB-key).
- `userCertificate`, `altSecurityIdentities` — explicit-mapping для AD CS
  (CVE-2022-26923 контекст).
- `unicodePwd`/`pwdLastSet` — сброс пароля.
- `sIDHistory` — SID-history injection (cross-forest abuse).
- `nTSecurityDescriptor` — ACL объекта; цель для AdminSDHolder-bypass
  (см. ниже).

**Attacker view.**

- WriteProperty `servicePrincipalName` на любого user ⇒ принудительный
  Kerberoasting (Target-spec через known DA → запрос ST → offline crack).
- WriteProperty `msDS-KeyCredentialLink` ⇒ Shadow Credentials: добавить
  свою WHfB-key ⇒ PKINIT-аутентификация ⇒ NT-hash через UnPAC-the-Hash.
- WriteProperty `userAccountControl` для выставления `DONT_REQUIRE_PREAUTH`
  ⇒ AS-REP roasting.
- WriteProperty `unicodePwd` или `User-Force-Change-Password` extended right
  ⇒ сброс пароля привилегированной учётки (если ACL разрешает).
- Member of `Domain Admins`/`Enterprise Admins`/`Schema Admins`/`Account Operators`
  /`Backup Operators`/`Server Operators`/`Print Operators` ⇒ путь к T0.
- Создание новой user-учётки в OU с делегированием Account Operators ⇒
  бэкдор.
- `sIDHistory` injection (требует особых условий: открытый SAM-RPC `MS-SAMR`
  на DC, тип trust) ⇒ pretend быть DA другого домена.

**Detection / GCNet.**

- Изменение членства в защищённых группах (см. `AdminSDHolder` чек-лист) —
  Critical.
- Появление SPN на учётке без него (особенно с `adminCount=1`) — Critical.
- Изменение `msDS-KeyCredentialLink` любого пользователя — High
  (проверять, что меняет владелец/admin, а не атакующий).
- `userAccountControl` смены к `TRUSTED_FOR_DELEGATION`,
  `TRUSTED_TO_AUTH_FOR_DELEGATION`, `DONT_REQUIRE_PREAUTH` — High.
- `unicodePwd` сбросы для DA/T0 — Critical; для остальных — корреляция
  с тикетом.
- `sIDHistory` smen — Critical.
- `nTSecurityDescriptor` смены на user → проверка ACE для
  `DS-Replication-Get-Changes-All` (DCSync), `User-Force-Change-Password`,
  `Self-Membership` (для group), `Reset-Password`, GenericAll/WriteDACL.

---

## group

**Назначение.** Группы безопасности и рассылки. Защищённые группы
(`adminCount=1`) автоматически получают ACL от `AdminSDHolder` каждые
60 минут (SDProp).

**Ключевые атрибуты.**

- `member` — членство; цель эскалации.
- `groupType` — флаги: Security/Distribution × Domain Local/Global/Universal.
- `adminCount` — флаг защищённой группы.
- `nTSecurityDescriptor` — ACL.
- `msDS-MembersOfResourcePropertyListBL` (DAC).

**Attacker view.**

- WriteProperty `member` (или extended right `Self-Membership`) ⇒ добавить
  себя в `Domain Admins` / `Enterprise Admins` / `Schema Admins` /
  `Backup Operators` / `Account Operators` / `Server Operators`.
- Создание новой группы с символическим именем «Help Desk» в защищённой
  OU и выдача через стороннее приложение — backdoor.
- Изменение `groupType` Domain Local → Universal/Global ⇒ изменение
  scope привилегий cross-domain.
- WriteDACL на группу ⇒ постоянный канал на изменение `member`.

**Detection / GCNet.**

- Любое изменение `member` для protected groups — Critical (даже если
  владелец-account legitimate, должно проходить через PIM/JIT).
- Изменение `adminCount` (особенно сброс с 1 в 0 — попытка убрать ACL
  AdminSDHolder, чтобы потом тихо WriteDACL — известный bypass) — High.
- Изменение `groupType` — High.

---

## computer

**Назначение.** `computer` наследует от `user`. Включает: рабочие станции,
серверы (T1), DC (T0). DC-учётки имеют флаг `SERVER_TRUST_ACCOUNT` в UAC
и SPN `HOST/`, `GC/`, `ldap/`, `RestrictedKrbHost/`. Машинная учётка
аутентифицируется паролем длины 240 байт, ротируемым каждые 30 дней
(если включено).

**Ключевые атрибуты безопасности.**

- `userAccountControl`: `WORKSTATION_TRUST_ACCOUNT`, `SERVER_TRUST_ACCOUNT`,
  флаги делегирования (см. [`user`](#user--person--organizationalperson)).
- `msDS-AllowedToActOnBehalfOfOtherIdentity` — **RBCD primitive**: SD на
  acceptor; кто записан, тот может S4U2Proxy-подменять любого юзера.
- `msDS-AllowedToDelegateTo` — constrained delegation цели.
- `msDS-KeyCredentialLink` — shadow credentials на computer (DC включительно).
- `servicePrincipalName` — SPN машины; добавление SPN HOST/x на чужой
  computer ⇒ возможность Kerberos AP-REQ к жертве от имени атакующего.
- `dNSHostName` — связан с SPN; смена ⇒ CVE-2022-26923 контекст
  (sAMAccountName spoofing → certificate request с UPN другого).
- `ms-Mcs-AdmPwd`, `ms-LAPS-Password`, `ms-LAPS-EncryptedPassword` —
  LAPS (legacy/Windows LAPS); чтение ⇒ локальный admin.
- `ms-FVE-RecoveryInformation` (под `computer`) — BitLocker recovery key.

**Attacker view.**

- WriteProperty `msDS-AllowedToActOnBehalfOfOtherIdentity` на target-сервер
  ⇒ RBCD: атакующий S4U2Self+S4U2Proxy получает ST к target от имени любого
  пользователя (включая DA, если target = DC).
- WriteProperty `servicePrincipalName` ⇒ Kerberoast machine account
  (длинные пароли, но всё равно offline target).
- Чтение LAPS-атрибутов ⇒ local admin на сотнях машин.
- Чтение BitLocker recovery key ⇒ offline-доступ к диску.
- Удаление computer DC и пересоздание под контролем атакующего —
  «Sticky Notes» бэкдор (S-1-5-…-1XXX RID повторно).
- Shadow Credentials (`msDS-KeyCredentialLink`) на DC ⇒ TGT за DC ⇒
  DCSync.

**Detection / GCNet.**

- `msDS-AllowedToActOnBehalfOfOtherIdentity` любая модификация — Critical
  (легитимные сценарии редки и должны быть документированы).
- `msDS-KeyCredentialLink` на computer — High; на DC — Critical.
- Изменения SPN на DC — Critical.
- LAPS/BitLocker reads — отдельный мониторинг (через 4662, не через
  объект-changes).
- `dNSHostName` mismatch с CN — High (CVE-2022-26923).

---

## msDS-GroupManagedServiceAccount / msDS-ManagedServiceAccount

**Назначение.** gMSA (групповой) / sMSA (одиночный) — учётные записи с
автоматической ротацией пароля и аутентификацией через Kerberos.
Пароль рассчитывается KDS root key + временной меткой и публикуется в
`msDS-ManagedPassword` (sMSA / gMSA). Для gMSA: атрибут
`msDS-GroupMSAMembership` — список SID, кто может читать пароль (хост-машины).

**Ключевые атрибуты.**

- `msDS-ManagedPassword` (gMSA): blob с текущим/предыдущим/будущим паролем.
- `msDS-ManagedPasswordId`, `msDS-ManagedPasswordPreviousId` — KDS-key id.
- `msDS-GroupMSAMembership` (gMSA) — SDDL с разрешёнными SID.
- `msDS-HostServiceAccount` (sMSA) — ссылка на host-`computer`.
- `servicePrincipalName` — задачи сервиса.

**Attacker view.**

- Чтение `msDS-ManagedPassword` (требует прав, прописанных в
  `msDS-GroupMSAMembership` или WriteProperty на этот атрибут) ⇒
  получение текущего blob ⇒ derive NT-hash ⇒ S4U/PtH.
- WriteProperty `msDS-GroupMSAMembership` (даже на одну минуту) ⇒
  добавить себя ⇒ прочитать пароль.
- Если gMSA — член привилегированной группы (наблюдается в реальных
  доменах) — компрометация = эскалация.
- KDS root key на DC: контроль ⇒ оффлайн-вычисление пароля любой gMSA
  без чтения атрибута на DC.

**Detection / GCNet.**

- Изменения `msDS-GroupMSAMembership` — Critical.
- Создание gMSA с членством в T0/T1-группах — Critical.
- Чтение `msDS-ManagedPassword` (через 4662) — мониторинг отдельно.

---

## foreignSecurityPrincipal

**Назначение.** `CN=ForeignSecurityPrincipals,DC=…` — объекты-плейсхолдеры
под внешние SID: well-known (S-1-1-0 Everyone, S-1-5-11 Authenticated Users)
и внешние SID из доверенных доменов/лесов. Имя CN = строка SID.

**Attacker view.**

- Содержимое FSP — индикатор для разведки: какие cross-forest SID имеют
  членство в локальных группах.
- В прошлом был вектор `S-1-5-21-0-0-0-XXX` (Allowed-To-Authenticate
  semantics) и SID-history pivots; современный SID-filter quarantine
  отсекает большинство.
- Изменение членства локальных групп через FSP-объект (`member` ссылается
  на FSP) — equivalent изменению `member` напрямую; проверять цепочку.

**Detection.** Создание новых FSP вне legitimate trust-cycle — High.

---

## msWMI-Som

**Назначение.** WMI-фильтр GPO. Хранит WQL-запрос(ы) в `msWMI-Parm2`,
которые исполняются на target-машине; GPO применяется только если запрос
вернул результат. Привязан к GPC через `gPCWQLFilter`. Default Security
Descriptor по схеме разрешает `Authenticated Users` чтение и
`Domain Admins` запись.

**Attacker view.**

- WriteProperty `msWMI-Parm2` на существующий WMI-фильтр ⇒ изменение
  scope применения GPO (например, расширить с тестовой OU на весь домен,
  или сузить так, чтобы выключить protective GPO на jump-server).
- Создание нового WMI-фильтра + привязка к подконтрольному GPO ⇒
  селективная RCE на машинах с заданными характеристиками.
- WQL-запрос исполняется в системном контексте — не RCE сам по себе,
  но влияет на routing GPO.

**Detection / GCNet.**

- Любое изменение `msWMI-Parm1`/`msWMI-Parm2` — High.
- Создание `msWMI-Som` объектов — High.
- Корреляция с изменениями `gPCWQLFilter` соответствующего GPC.

---

## classStore / packageRegistration / intellimirrorSCP

**Назначение.** Семейство объектов GPSI (Group Policy Software Installation).
`classStore` — контейнер, висит под GPC; `packageRegistration` — описывает
конкретный MSI/ZAP пакет (атрибуты `msiFileList`, `msiScript`,
`packageType`, `installUiLevel`); `intellimirrorSCP` — старый IntelliMirror
SCP. Установка идёт в SYSTEM-контексте на target.

**Attacker view.**

- Создание `packageRegistration` в любом GPC, привязанном к target-OU,
  с UNC-путём на подконтрольную шару с MSI ⇒ при следующем GPO-refresh
  msiexec /i под SYSTEM ⇒ RCE на всех target-машинах.
- WriteProperty `msiFileList` существующего пакета ⇒ замена на
  trojanized MSI без изменения GPO-структуры ⇒ медленный roll-out.

**Detection / GCNet.**

- Создание `packageRegistration` — Critical (редкое и заметное событие).
- WriteProperty `msiFileList`, `msiScript`, `packageType` — Critical.
- Корреляция с SYSVOL-файлами (если `msiFileList` указывает на SYSVOL).

---

## mSSMS-семейство (SCCM / MECM)

**Назначение.** SCCM/MECM публикует Management Point, Site, Boundary
ranges в AD как SCP-классы. Клиенты находят MP через AD-lookup и
доверяют ему политики (включая applications с install-as-system).

**Attacker view.**

- Создание/подмена `mSSMSManagementPoint` SCP с подконтрольным MP
  endpoint ⇒ клиенты получают политики атакующего ⇒ массовая
  RCE через SCCM Application deployment под SYSTEM.
- Изменение `mSSMSSite` ⇒ влияние на site-routing.
- `mSSMSRoamingBoundaryRange` smens ⇒ перенаправление клиентов между
  сайтами.

**Detection / GCNet.**

- Создание/удаление `mSSMSManagementPoint` или `mSSMSSite` вне
  ConfigMgr-плановых операций — Critical.
- Любые изменения SCP-атрибутов с упоминанием URL/host — High.

---

## organizationalUnit / container / builtinDomain

**Назначение.** Контейнерные классы. `organizationalUnit` поддерживает
`gPLink` и собственные ACL (делегирование); `container` — системный
(non-OU) контейнер (включая `CN=AdminSDHolder,CN=System,DC=…`,
`CN=Users`, `CN=Computers`); `builtinDomain` — `CN=Builtin,DC=…` с
default-группами Administrators/Backup Operators/Print Operators/etc.

**Attacker view.**

- WriteDACL/Owner на OU ⇒ полный контроль над всеми объектами под ней
  через ACL-наследование (если `inheritOnly` ACE на childObjectType).
- WriteProperty на `nTSecurityDescriptor` `CN=AdminSDHolder` ⇒ через
  60 минут SDProp пропагирует ACE на все защищённые объекты ⇒
  persistent-доступ к DA/EA. Классическая «AdminSDHolder backdoor».
- WriteProperty `gPLink` на OU ⇒ привязка вредоносного GPO к участку
  иерархии (например, к `OU=Tier-0`, `OU=Domain Controllers`).
- Создание delegated-OU «помощникам» с правами на user reset password —
  insider-вектор.

**Detection / GCNet.**

- Изменение `nTSecurityDescriptor` `CN=AdminSDHolder` — **Critical, всегда**.
- Изменение `gPLink` на любую OU/контейнер — High; на `OU=Domain Controllers` — Critical.
- ACL-смены на корневых OU/контейнерах — High.

---

## serviceConnectionPoint / serviceAdministrationPoint

**Назначение.** SCP — публикация серверного приложения в AD (Exchange,
SCCM, AD CS, кастомные сервисы). Клиенты находят сервис через
`(objectClass=serviceConnectionPoint)(keywords=…)`. Атрибуты:
`serviceBindingInformation` (URI/URL), `serviceClassName`, `keywords`,
`serviceDNSName`.

**Attacker view.**

- Создание rogue-SCP, вынуждающего привилегированный клиент (например,
  Exchange, AD CS, ConfigMgr admin tool) аутентифицироваться к
  подконтрольному endpoint ⇒ NTLM/Kerberos relay.
- WriteProperty `serviceBindingInformation` существующего SCP легитимного
  сервиса ⇒ silent редирект клиентов.

**Detection / GCNet.**

- Создание SCP под `computer` без соответствующей роли — High.
- Изменение `serviceBindingInformation` существующих SCP — High.

---

## rRASAdministrationConnectionPoint

**Назначение.** SCP RRAS-сервера (Routing and Remote Access). По
[MS Learn](https://learn.microsoft.com/en-us/windows/win32/adschema/c-rrasadministrationconnectionpoint):
«This object contains the connection point for RRAS». Указывает клиентам
RRAS-консоли/админ-инструментов, где находится сервер.

**Attacker view.** Аналогично [SCP](#serviceconnectionpoint--serviceadministrationpoint):
rogue-RRAS-SCP может склонить администратора подключиться к подконтрольному
endpoint. RAS-серверы — periметральные, поэтому компрометация = pivot
из/в внутреннюю сеть.

**Detection.** Создание/удаление — High; изменения `serviceBindingInformation` — High.

---

## ipsec-классы

**Назначение.** Legacy-классы IPSec policy в AD (`ipsecBase`,
`ipsecNegotiationPolicy`, `ipsecISAKMPReference`, `ipsecFilter` и т. д.).
Современные доменные политики IPSec доставляются через GPO Windows Firewall
with Advanced Security; AD-классы остаются для совместимости с Windows 2000-эры
конфигурациями.

**Attacker view.**

- Изменение IPSec policy через AD-объекты ⇒ MITM/decrypt-by-design (если
  политика разрешает clear-text fallback или подменяет KE-параметры).
- Удаление защищающей политики ⇒ downgrade на cleartext.

**Detection.** Любые изменения — High; в большинстве доменов классы статичны.

---

## Wi-Fi Group Policy классы

**Назначение.** `ms-net-ieee-80211-GroupPolicy` (новый формат) и
`msieee80211-Policy` (legacy) — доставка 802.11 профилей беспроводной сети
через GPO. По [MS Learn](https://learn.microsoft.com/en-us/windows/win32/adschema/c-ms-net-ieee-80211-grouppolicy):
«This class represents an 802.11 wireless network Group Policy object…
contains identifiers and configuration data relevant to an 802.11 wireless
network.» Соответствующие атрибуты содержат XML-blob с SSID, режимом
аутентификации (WPA2-Enterprise, PSK), сертификатами, EAP-настройками.

**Attacker view.**

- Чтение объектов даёт PSK / EAP-конфиги (если PSK хранится в открытом
  виде в profile blob — для legacy WPA2-PSK).
- WriteProperty ⇒ доставка вредоносного Wi-Fi профиля (например,
  ослабление до open-network) на target-машины.

**Detection.** Изменения — Medium; реальных модификаций крайне мало.

---

## msDS-DeviceContainer

**Назначение.** Контейнер `CN=RegisteredDevices,DC=…` для объектов
`msDS-Device`, создаваемых при Hybrid Azure AD Join / Workplace Join.
Содержит device-ID, ключи, привязку к user.

**Attacker view.**

- Регистрация подконтрольного устройства в Hybrid AAD-окружении ⇒
  получение PRT (Primary Refresh Token) после coerced sign-in ⇒
  дальнейший pivot в Entra ID.
- WriteProperty на существующий `msDS-Device` (привязка к другому user
  или подмена `msDS-DeviceObjectVersion`) ⇒ device-impersonation.

**Detection.** Создание/удаление `msDS-Device` объектов — Medium;
изменения атрибутов конкретного device — Medium.

---

## ms-srvShareMapping

**Назначение.** Расширение схемы для роуминга маппингов сетевых дисков
(Folder Redirection / Roaming Profiles). Хранит per-user соответствие
«буква диска → UNC». Часто наблюдается в большом количестве (1000+) —
по записи на пользователя.

**Attacker view.**

- WriteProperty `ms-srvShareMappingPath` (или эквивалент) ⇒ редирект
  пользовательских маппингов на подконтрольную шару ⇒ при открытии
  «своего» диска пользователь работает с rogue-сервером (включая
  возможность подмены файлов и кражу credentials через NTLM).
- Бэкдор-вариант `Folder Redirection` через AD-объект, минуя GPO.

**Detection.** Массовые изменения `ms-srvShareMapping` для разных user —
High; одиночные изменения — Medium.

---

## Приложение A. Глоссарий техник

| Техника                                          | Краткое описание                                                                                                                                                                         |
| ------------------------------------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **DCSync**                                       | Извлечение секретов AD через DRSUAPI (`DRSGetNCChanges`); требует extended rights `DS-Replication-Get-Changes` + `…-Get-Changes-All` (+ `…-Get-Changes-In-Filtered-Set` для RODC).       |
| **Golden Ticket**                                | Forge TGT с произвольным PAC, подписанный ключом `krbtgt`.                                                                                                                               |
| **Silver Ticket**                                | Forge ST к конкретному сервису, подписанный NT-hash сервисной учётки.                                                                                                                    |
| **Trust Ticket / Inter-Realm Forge**             | Forge inter-realm TGT через TDO trust key из `trustAuthIncoming/Outgoing`.                                                                                                               |
| **Kerberoasting**                                | Запрос ST для SPN-носителя ⇒ offline-перебор пароля сервисной учётки (RC4-HMAC / AES).                                                                                                   |
| **AS-REP roasting**                              | Запрос AS-REP для учётки с `DONT_REQUE_PREAUTH` ⇒ offline-перебор.                                                                                                                       |
| **Unconstrained delegation**                     | `TRUSTED_FOR_DELEGATION` UAC; пользовательский TGT попадает на сервер ⇒ extract & reuse.                                                                                                 |
| **Constrained delegation (S4U2Proxy)**           | `msDS-AllowedToDelegateTo`: сервис может запросить ST к target-SPN от имени любого user (классический S4U2Proxy без protocol transition или с ним при `TRUSTED_TO_AUTH_FOR_DELEGATION`). |
| **RBCD (Resource-Based Constrained Delegation)** | `msDS-AllowedToActOnBehalfOfOtherIdentity` на target — кто записан, может S4U-impersonate любого user (включая DA) к target.                                                             |
| **S4U2Self**                                     | Получение ST к самому себе от имени любого user (без preauth жертвы). Комбинируется с S4U2Proxy.                                                                                         |
| **Shadow Credentials**                           | Запись WHfB-key в `msDS-KeyCredentialLink` ⇒ PKINIT-аутентификация ⇒ TGT + NT-hash через UnPAC.                                                                                          |
| **AdminSDHolder backdoor**                       | ACE на `CN=AdminSDHolder,CN=System` ⇒ через 60 минут SDProp пропагирует на все protected objects (`adminCount=1`).                                                                       |
| **ADIDNS spoofing**                              | Создание `dnsNode` (`wpad`, `*`, отсутствующие имена) в AD-integrated DNS-зоне ⇒ NTLM relay.                                                                                             |
| **GPO injection**                                | Запись в `gPCFileSysPath` (SYSVOL) — `Scripts.ini`, `Registry.pol`, `ScheduledTasks.xml`, MSI install — для RCE на linked-OU.                                                            |
| **SYSVOL tampering**                             | Прямая запись в `\\<domain>\SYSVOL\<domain>\Policies\…`; требует write на DFSR/NTFRS реплику.                                                                                            |
| **SCCM compromise**                              | Подмена SCP `mSSMSManagementPoint` или политика SCCM Application с install-as-system ⇒ RCE на клиентах.                                                                                  |
| **Pre-Windows 2000 Compatible Access**           | Историческая группа с правами на чтение всех user-атрибутов; присутствие нестандартных членов = риск.                                                                                    |
| **SID-history injection**                        | Запись `sIDHistory` user/group с SID привилегированной группы из доверенного домена; обходит SID-filter quarantine, если он отключён.                                                    |
| **CVE-2022-26923 (Certifried)**                  | Подмена `dNSHostName` computer-учётки + AD CS template с UPN-mapping ⇒ certificate с identity DC.                                                                                        |

## Приложение B. Ссылки и литература

- [Active Directory Schema (MS Learn index)](https://learn.microsoft.com/en-us/windows/win32/adschema/active-directory-schema)
- [\[MS-ADTS\] Active Directory Technical Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/d2435927-0999-4c62-8c6d-13ba31a52e1a)
- [\[MS-DRSR\] Directory Replication Service (DRS) Remote Protocol](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/f977faaa-673e-4f66-b9bf-48c640241d47)
- [Securing Privileged Access — tiered model](https://learn.microsoft.com/en-us/security/privileged-access-workstations/privileged-access-access-model)
- [Protected Users Security Group](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group)
- [AdminSDHolder, Protected Groups and SDPROP](<https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/dd220680(v=ws.10)>)
- [MITRE ATT&CK: Active Directory tactics](https://attack.mitre.org/)
- [Windows LAPS overview](https://learn.microsoft.com/en-us/windows-server/identity/laps/laps-overview)
- [Kerberos Constrained Delegation Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
