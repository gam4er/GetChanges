# GetChanges (framework branch)

GetChanges is a Windows console tool that watches Active Directory for object changes via an LDAP **persistent search** and writes one indented JSON file per qualified change to a local output directory. This `framework` branch targets **.NET Framework 4.8** for environments that cannot run .NET 10 (the modern variant lives on `devel`).

> All deep links in this document point at the `framework` branch on GitHub. If line numbers shift, update the links alongside the code (see [AGENTS.md](AGENTS.md)).

---

## 1. What it does — at a glance

1. Discovers (or accepts) the best Domain Controller, binds an authenticated `LdapConnection`, and caches the selected DC for the lifetime of the process.
2. Optionally pre-loads a **baseline snapshot** of the tracked attributes for every object under the search base — used to suppress notifications that don't actually change a tracked attribute.
3. Issues a single LDAP persistent search (`DirectoryNotificationControl`) and asynchronously consumes incremental change entries.
4. Filters out DNs matching ignore patterns; for the rest, parses the entry into a property bag.
5. Pushes events through a small in-process **producer/consumer pipeline** (two unbounded `BlockingCollection<>` queues).
6. Optionally enriches events with `msDS-ReplAttributeMetaData` from the DC.
7. Writes each qualifying event as a standalone, timestamped JSON file via a single-writer file sink.
8. Updates a live Spectre.Console status line with notification and write counters; reconnects with capped exponential backoff + jitter on transient LDAP failures and forces DC rediscovery on each reconnect.

---

## 2. Quick start

```powershell
# VS 2022 Developer PowerShell
& 'C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\Launch-VsDevShell.ps1' -SkipAutomaticLocation

# Restore packages.config (msbuild restore does NOT cover packages.config projects)
Invoke-WebRequest https://dist.nuget.org/win-x86-commandline/latest/nuget.exe `
  -OutFile "$env:USERPROFILE\.nuget\nuget.exe"
& "$env:USERPROFILE\.nuget\nuget.exe" restore GetChanges.sln

# Build
msbuild GetChanges.sln /p:Configuration=Release /v:minimal

# Run
GCNet\bin\Release\GCNet.exe --base-dn "DC=corp,DC=local"
GCNet\bin\Release\GCNet.exe --help
```

Press **ENTER** or **CTRL+C** to stop the monitor cleanly (cooperative cancellation, then bounded waits — see [`MonitoringLifecycleService`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/MonitoringLifecycleService.cs#L24)).

---

## 3. Requirements

- Windows with .NET Framework 4.8 runtime present.
- Visual Studio 2022 + MSBuild 17.x (Build Tools edition is fine).
- Domain-joined account with permission to read directory data and (if `--enrich-metadata`) `msDS-ReplAttributeMetaData`.
- Outbound LDAP/LDAPS reachability to at least one DC.

---

## 4. CLI reference

All options are defined in [`Hosting/Options.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/Options.cs#L8):

| Option | Description |
| --- | --- |
| `--base-dn <DN>` | Search root. Defaults to `defaultNamingContext`. |
| `--enrich-metadata` | Attach `msDS-ReplAttributeMetaData` to each event. |
| `--tracked-attributes a,b,c` | Comma-separated attribute list. When set, only changes affecting these attributes produce a file; baseline snapshot is loaded at startup. |
| `--dn-ignore-list <path>` | File with substring DN filters (one per line). Default: `dn-ignore-default.txt`. |
| `--output-dir <path>` | Directory for JSON event files. Default: `.\output`. |
| `--phantom-root` | Enable LDAP `SearchOption.PhantomRoot` for the persistent search. |
| `--dc <fqdn>` | Force a specific DC (combine with `--dc-selection manual`). |
| `--dc-selection auto\|manual` | DC selection strategy. Default: `auto`. |
| `--prefer-site-local` | Prefer healthy DCs in the local AD site. Default: `true`. |

---

## 5. Architecture

```
                +--------------------------+
                |  GetChanges.Main         |  Hosting/GetChanges.cs
                |  (Spectre.Console.Cli)   |
                +-----------+--------------+
                            |
                            v
                +--------------------------+
                |  ChangeMonitorApplication|  Hosting/ChangeMonitorApplication.cs
                |  - validates options     |
                |  - wires subsystems      |
                |  - owns lifecycle/status |
                +---+-----------+----------+
                    |           |
       +------------+           +-------------------+
       v                                            v
+-------------------+                    +-------------------------+
| LdapConnection    |                    | BaselineSnapshotLoader  |  Pipeline/BaselineSnapshotLoader.cs
| Factory           |                    | (optional, when         |
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
          | OnNotificationReceived()                   | (filters by tracked-attribute diff,
          | OnBeforeReconnect() ------> resets DC      |  emits {attr}_old / {attr}_new pairs,
          |                              cache         |  optional MetadataEnricher)
          v                                            v
   counters / status line                       counters / status line
```

Key cross-cutting facts:

- **Single namespace** `GCNet`, folders express grouping only — minimises `using` churn.
- Two **unbounded** in-process queues (`incoming`, `outgoing`) decouple the LDAP callback from disk I/O. See note in [`ChangeProcessingPipeline`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ChangeProcessingPipeline.cs#L23).
- The notification loop is the only component that reconnects; on each reconnect it invokes `OnBeforeReconnect`, which clears the cached DC name in the connection factory so a fresh DC is picked next attempt.

---

## 6. Subsystems

### 6.1 Entry point and CLI ([`Hosting/GetChanges.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/GetChanges.cs#L9))

- `Main` runs a Spectre.Console.Cli `CommandApp<RunCommand>`.
- `RunCommand.Execute` wraps the application in `AnsiConsole.Status(...)` so the orchestrator can update a live status line, then delegates to [`ChangeMonitorApplication.Run`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L41).
- Top-level exceptions are caught and logged via [`AppConsole.WriteException`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/AppConsole.cs#L19).

### 6.2 Application orchestrator ([`Hosting/ChangeMonitorApplication.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L13))

- Holds the `_baseline` `ConcurrentDictionary` and counters (`_notificationCount`, `_eventsWrittenCount`).
- Wires: connection factory → baseline loader → pipeline → writer → notification loop, with [`MonitoringLifecycleService`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/MonitoringLifecycleService.cs#L16) supplying the cancellation token.
- `BuildNotificationLoopContext` registers `OnBeforeReconnect = _connectionFactory.ResetCachedDomainController` so each reconnect attempt forces fresh DC selection — see [line 88](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L88).
- Status line is rebuilt on every notification and every successful file write — see [`UpdateStatus`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L172). Counters are read with `Interlocked.Read` for a torn-write-free view.

### 6.3 Process lifecycle ([`Hosting/MonitoringLifecycleService.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/MonitoringLifecycleService.cs#L16))

- Creates a `CancellationTokenSource` plus a `ManualResetEventSlim` stop signal.
- `WaitForStopSignal` listens for `ENTER` and `CTRL+C` simultaneously, so either path terminates the program cleanly.
- `WaitForTask`/`WaitForTasks` give the orchestrator bounded shutdown timeouts so a stuck LDAP callback cannot hang process exit forever.

### 6.4 Best-DC auto-discovery ([`Ldap/DomainControllerSelector.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/DomainControllerSelector.cs#L20))

- `SelectBestDomainController(options, out reason)` honours `--dc` / `--dc-selection manual` first, otherwise enumerates DCs via `System.DirectoryServices.ActiveDirectory`, prefers the local AD site when `--prefer-site-local` is set, and probes candidates for health.
- The chosen DC and the human-readable selection reason are logged once.

### 6.5 Connection factory and DC cache ([`Ldap/LdapConnectionFactory.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapConnectionFactory.cs#L22))

- Caches the selected DC under `_cacheLock` so DC discovery runs **once** at startup (and again only on reconnect).
- [`ResetCachedDomainController`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapConnectionFactory.cs#L36) is invoked from the notification loop's `OnBeforeReconnect` callback to drop the cache; the next [`CreateBoundConnection`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapConnectionFactory.cs#L50) call rediscovers.
- Configures protocol v3, `AutoReconnect`, no referral chasing, best-effort TCP keep-alive, and `AuthType.Negotiate` with `AutoBind`.
- **SECURITY NOTE:** server certificate validation is disabled — see the warning at [line 85](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapConnectionFactory.cs#L85).

### 6.6 Persistent-search notification loop ([`Ldap/LdapNotificationLoopService.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapNotificationLoopService.cs#L46))

- Runs `RunAsync(NotificationLoopContext, CancellationToken)`. Each attempt opens an `LdapConnection`, attaches `DirectoryNotificationControl` (and optionally `SearchOptionsControl(PhantomRoot)`), and starts a `BeginSendRequest` callback that delivers partial results to `OnPartialResults` (line 186).
- DN ignore filtering (`ShouldIgnoreByDn`, line 254) drops unwanted entries before parsing.
- Each forwarded entry is parsed by [`LdapEntryParser`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapEntryParser.cs) and pushed to the pipeline's incoming queue; `OnNotificationReceived` is fired for the status counter.
- On `IsRecoverableNotificationException` (line 272) the loop:
  1. Increments the attempt counter.
  2. Invokes `OnBeforeReconnect` (clears DC cache).
  3. Sleeps `CalculateReconnectDelay(attempt)` — exponential growth capped at 60s with jitter, using a process-wide `Random` guarded by a lock (no `Random.Shared` on .NET Framework 4.8).

### 6.7 Entry parsing ([`Ldap/LdapEntryParser.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapEntryParser.cs))

- Converts a `SearchResultEntry` into a `Dictionary<string, object>` plus an `objectGUID`.
- Decodes binary AD attributes (SID, GUID, file-time, security descriptors) into shapes friendly to JSON / SharpHound conventions.

### 6.8 Baseline snapshot ([`Pipeline/BaselineSnapshotLoader.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/BaselineSnapshotLoader.cs#L21))

- Triggered only when `--tracked-attributes` is supplied.
- Walks the search base with paged search and, for every object, captures canonical JSON values of the tracked attributes via [`CanonicalValueHelper`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/CanonicalValueHelper.cs#L7).
- Stores results in the shared `ConcurrentDictionary<string, BaselineEntry>` keyed by [`ObjectKeyBuilder.BuildObjectKey`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ObjectKeyBuilder.cs#L9) (objectGUID when available, otherwise SHA hash of DN).

### 6.9 Pipeline and queues ([`Pipeline/ChangeProcessingPipeline.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ChangeProcessingPipeline.cs#L23))

- Two `BlockingCollection<T>` instances over `ConcurrentQueue<T>`:
  - `Incoming` — populated by the LDAP callback thread.
  - `Outgoing` — drained by the writer task in the orchestrator.
- [`StartAsync`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ChangeProcessingPipeline.cs#L47) consumes `Incoming`. For each event:
  1. If `--tracked-attributes` is set, [`ShouldWriteWhenTrackedAttributesChanged`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ChangeProcessingPipeline.cs#L80) compares canonical JSON of each tracked attribute against the baseline; updates baseline; emits `{attr}_old` / `{attr}_new` pairs only on real change.
  2. If `--enrich-metadata` is set, calls `MetadataEnricher.TryLoadMetadata`.
  3. Adds the resulting property bag to `Outgoing`.

### 6.10 Metadata enrichment ([`Ldap/MetadataEnricher.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/MetadataEnricher.cs#L20))

- Lazily holds a private `LdapConnection` (the user's connection is reserved for the persistent search).
- Reads `msDS-ReplAttributeMetaData` for the changed object and parses each XML record.
- Resets and reopens the helper connection on errors so transient failures don't poison subsequent calls.

### 6.11 Output writer / file sink ([`Output/EventFileWriter.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Output/EventFileWriter.cs#L16))

- One JSON file per qualifying event, named `{yyyyMMdd_HHmmss_fff}_{sanitized-DN}.json`.
- Internal lock serialises `WriteEvent` so the unique-name counter never races and produces partially-written files.
- Stems are capped at 180 characters to stay within Windows path limits.
- After every successful write the orchestrator's [`OnFileWritten`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L166) increments the writer counter and refreshes the status line.

### 6.12 Console / status ([`Hosting/AppConsole.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/AppConsole.cs#L6))

- All log output goes through `AppConsole.Log` and `AppConsole.WriteException` so the Spectre.Console status spinner is not torn by ad-hoc `Console.WriteLine` calls.
- Status format (in `UpdateStatus`): `[grey]{timestamp}[/] notifications: [yellow]{n}[/]  written: [green]{m}[/]`.

### 6.13 Pipeline metrics ([`Pipeline/PipelineMetrics.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/PipelineMetrics.cs#L5))

- Lightweight in-memory counters: queued/processed events, written events, metadata errors, writer errors, processing errors. Logged periodically via `MaybeLogSnapshot`.

---

## 7. Data structures

| Type | File | Purpose |
| --- | --- | --- |
| `Options` | [`Hosting/Options.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/Options.cs#L8) | Parsed CLI options (Spectre.Console.Cli `CommandSettings`). |
| `ChangeEvent` | [`Models/ChangeEvent.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Models/ChangeEvent.cs#L12) | Raw entry + parsed property bag travelling through the pipeline. |
| `BaselineEntry` | [`Models/BaselineEntry.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Models/BaselineEntry.cs#L10) | Per-object canonical JSON of tracked attributes. |
| `NotificationLoopContext` | [`Ldap/LdapNotificationLoopService.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapNotificationLoopService.cs) | Bag of inputs for one notification-loop run (base DN, factory, target queue, ignore filters, callbacks). |
| `MetadataEnrichmentResult` | [`Ldap/MetadataEnricher.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/MetadataEnricher.cs#L13) | Parsed `msDS-ReplAttributeMetaData` entries. |
| `BlockingCollection<ChangeEvent>` (incoming) and `BlockingCollection<Dictionary<string,object>>` (outgoing) | [`Pipeline/ChangeProcessingPipeline.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ChangeProcessingPipeline.cs#L25) | The two queues bridging notification, processing, and writing. |
| `ConcurrentDictionary<string, BaselineEntry>` | [`Hosting/ChangeMonitorApplication.cs`](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L15) | Shared baseline state, keyed by `ObjectKeyBuilder.BuildObjectKey`. |

---

## 8. End-to-end algorithm

1. **CLI parsing.** `Main` ([Hosting/GetChanges.cs:11](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/GetChanges.cs#L11)) hands control to Spectre.Console.Cli, which materialises `Options` and invokes `RunCommand.Execute`.
2. **Status spinner.** `RunCommand.Execute` ([Hosting/GetChanges.cs:20](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/GetChanges.cs#L20)) starts `AnsiConsole.Status` and calls `ChangeMonitorApplication.Run`.
3. **Validate options.** `ValidateDomainControllerOptions` ([Hosting/ChangeMonitorApplication.cs:126](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L126)) rejects inconsistent `--dc-selection`/`--dc` combinations.
4. **DC discovery + bind.** `LdapConnectionFactory.CreateBoundConnection` ([Ldap/LdapConnectionFactory.cs:50](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapConnectionFactory.cs#L50)) selects the best DC via `DomainControllerSelector` ([Ldap/DomainControllerSelector.cs:28](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/DomainControllerSelector.cs#L28)) and caches the DC name under a lock.
5. **Resolve base DN.** When omitted, `GetBaseDn` ([Hosting/ChangeMonitorApplication.cs:203](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L203)) reads `defaultNamingContext` from RootDSE.
6. **Load DN ignore list.** Substring filters parsed from `--dn-ignore-list`.
7. **Parse tracked-attributes.** Empty list → "write everything"; non-empty → snapshot loading is required.
8. **Baseline snapshot (optional).** `BaselineSnapshotLoader.LoadInitialSnapshot` ([Pipeline/BaselineSnapshotLoader.cs:30](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/BaselineSnapshotLoader.cs#L30)) page-walks the search base and populates the baseline dictionary.
9. **Build pipeline + writer.** `ChangeProcessingPipeline` and `EventFileWriter` are instantiated; the writer uses `--output-dir` (default `.\output`).
10. **Spawn workers.** `pipeline.StartAsync` and `StartWriterLoop` ([Hosting/ChangeMonitorApplication.cs:108](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L108)) run on the thread pool.
11. **Start notification loop.** `LdapNotificationLoopService.RunAsync` ([Ldap/LdapNotificationLoopService.cs:46](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapNotificationLoopService.cs#L46)) issues the persistent search.
12. **Per-notification flow.** Inside `OnPartialResults` ([Ldap/LdapNotificationLoopService.cs:186](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapNotificationLoopService.cs#L186)): apply DN filter → parse via `LdapEntryParser` → enqueue `ChangeEvent` to `Incoming` → fire `OnNotificationReceived` (counter + status refresh).
13. **Pipeline filtering.** `ShouldWriteWhenTrackedAttributesChanged` ([Pipeline/ChangeProcessingPipeline.cs:80](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Pipeline/ChangeProcessingPipeline.cs#L80)) compares canonical JSON of each tracked attribute against the baseline. On real change emits `_old` / `_new` pairs and updates baseline atomically.
14. **Metadata enrichment (optional).** `MetadataEnricher.TryLoadMetadata` adds `msdsReplAttributeMetaData` to the property bag.
15. **Forward to writer queue.** Property bag is added to `Outgoing`.
16. **Write JSON file.** `EventFileWriter.WriteEvent` ([Output/EventFileWriter.cs:29](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Output/EventFileWriter.cs#L29)) builds a unique path and serialises with `Newtonsoft.Json` (indented, UTF-8 no BOM).
17. **Update writer counter.** `OnFileWritten` ([Hosting/ChangeMonitorApplication.cs:166](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/ChangeMonitorApplication.cs#L166)) increments `_eventsWrittenCount` and refreshes the status line.
18. **Reconnect on transient errors.** When `IsRecoverableNotificationException` ([Ldap/LdapNotificationLoopService.cs:272](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Ldap/LdapNotificationLoopService.cs#L272)) returns true, the loop fires `OnBeforeReconnect` (resets the cached DC), sleeps `CalculateReconnectDelay(attempt)` (capped at 60s with jitter), and retries.
19. **Stop signal.** `MonitoringLifecycleService.WaitForStopSignal` ([Hosting/MonitoringLifecycleService.cs:24](https://github.com/gam4er/GetChanges/blob/framework/GCNet/Hosting/MonitoringLifecycleService.cs#L24)) unblocks on ENTER or CTRL+C.
20. **Cooperative shutdown.** `RequestStop` cancels the token; the orchestrator waits up to 5s for the notification loop, then completes the `Incoming` queue, then waits up to 5s for the worker and writer tasks. Bounded waits guarantee process exit.

---

## 9. Build, run, publish

- **Restore:** `& "$env:USERPROFILE\.nuget\nuget.exe" restore GetChanges.sln`
- **Build (Release):** `msbuild GetChanges.sln /p:Configuration=Release /v:minimal`
- **Output:** `GCNet\bin\Release\GCNet.exe` (Costura.Fody embeds dependencies into the single executable; see `GCNet/FodyWeavers.xml`).
- **Submodule:** `SharpHoundCommon/` is consumed via project reference at `net472`. Initialise with `git submodule update --init --recursive`.

---

## 10. Security notes

- **Sensitive output.** JSON event files reproduce directory data verbatim (including ACEs, SIDs, attribute history). Treat the output directory as sensitive; rotate / scope access.
- **Disabled certificate validation.** `LdapConnectionFactory` short-circuits `VerifyServerCertificate` to allow internal AD lab use. Replace with a real validator before any external deployment — see the inline `SECURITY` comment.
- **Account privileges.** The bound principal can read everything the configured `--base-dn` allows; principle of least privilege applies.

---

## 11. Future work / ideas

- Bound the in-process queues so a slow disk cannot grow process memory unbounded.
- Parallelise DC health probes during `auto` selection.
- Migrate logging from `AppConsole` to `Microsoft.Extensions.Logging`.
- Surface pipeline metrics over `EventCounters` / ETW.
- Optional per-attribute tombstone tracking.

---

## 12. Related documents

- [AGENTS.md](AGENTS.md) — coding style, build commands, required-to-update files for this branch.
- `SharpHoundCommon/README.md` — submodule overview and tests.
