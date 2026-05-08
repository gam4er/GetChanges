# GetChanges

Real-time Active Directory object change monitor. Uses LDAP persistent-search notifications (`DirectoryNotificationControl`) to receive change events immediately as they occur in AD, correlates them against an in-memory baseline snapshot, and writes each qualifying event to a timestamped JSON file.

Runs on **.NET 10 / Windows**, requires only a domain account with read access to the monitored OU.

---

## Quick Start

```powershell
dotnet build GetChanges.sln -c Release

GCNet\bin\Release\net10.0-windows\GCNet.exe `
  --tracked-attributes userAccountControl,pwdLastSet,badPasswordTime,mail
```

---

## Requirements

| Requirement | Value |
|---|---|
| .NET SDK | 10.x (`net10.0-windows`) |
| OS | Windows (uses `System.DirectoryServices.Protocols`, Win32 advapi32) |
| Permissions | Domain account with read access to the monitored DN |

---

## Command-Line Reference

| Flag | Default | Description |
|---|---|---|
| `--base-dn` | `defaultNamingContext` from RootDSE | Base DN for all searches and notifications |
| `--tracked-attributes` | _(none — all changes written)_ | Comma-separated attribute names; only events where at least one listed attribute changed are written |
| `--enrich-metadata` | `false` | Attach `msDS-ReplAttributeMetaData` to every output event |
| `--dn-ignore-list` | `dn-ignore-default.txt` | Path to a file with substring DN filters (one per line); matching objects are silently skipped |
| `--output-dir` | `.\output` | Directory for JSON event files (absolute or relative) |
| `--phantom-root` | `false` | Use `SearchOption.PhantomRoot` so the notification covers all NCs visible from the connected DC |
| `--dc` | _(auto-discovered)_ | Explicit domain controller FQDN |
| `--dc-selection` | `auto` | `auto` — probe and rank discovered DCs; `manual` — use `--dc` only |
| `--prefer-site-local` | `true` | In `auto` mode, prefer DCs in the local AD site |

### Examples

```powershell
# Monitor specific attributes (tracked mode)
GCNet.exe --tracked-attributes "member,adminCount,userAccountControl"

# Explicit DC, full stream with metadata enrichment
GCNet.exe --dc dc01.corp.local --dc-selection manual --enrich-metadata

# PhantomRoot — monitor all naming contexts visible from GC port
GCNet.exe --phantom-root --base-dn "DC=corp,DC=local"
```

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│                    ChangeMonitorApplication                       │
│                                                                  │
│  ┌──────────────────────┐   ┌────────────────────────────────┐   │
│  │ BaselineSnapshotLoader│  │ LdapNotificationLoopService    │   │
│  │                      │   │                                │   │
│  │ One-shot LDAP search  │   │ Persistent-search loop:        │   │
│  │ for tracked attrs.    │   │  • receives LDAP notifications │   │
│  │ Populates _baseline   │   │  • parses entries              │   │
│  │ dictionary.           │   │  • enqueues ChangeEvents       │   │
│  └──────────────────────┘   │                                │   │
│                              │ On error: calls               │   │
│                              │  OnBeforeReconnect (clears    │   │
│                              │  DC cache) then retries with  │   │
│                              │  exp backoff + jitter.        │   │
│                              └────────────────────────────────┘  │
│                                           │                      │
│                                           ▼                      │
│                         ┌────────────────────────────────────┐   │
│                         │     ChangeProcessingPipeline       │   │
│                         │                                    │   │
│                         │  Worker thread:                    │   │
│                         │  • compare attrs vs baseline       │   │
│                         │  • filter by trackedAttributes     │   │
│                         │  • optionally enrich metadata      │   │
│                         │  • update baseline                 │   │
│                         │  • enqueue to Outgoing queue       │   │
│                         └────────────────────────────────────┘   │
│                                           │                      │
│                                           ▼                      │
│                         ┌────────────────────────────────────┐   │
│                         │         EventFileWriter            │   │
│                         │                                    │   │
│                         │  Writer thread:                    │   │
│                         │  • dequeue from Outgoing           │   │
│                         │  • write JSON →                    │   │
│                         │    {timestamp}_{dn}.json           │   │
│                         └────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

---

## Subsystem Descriptions

### [`GCNet/GetChanges.cs`](GCNet/GetChanges.cs)

Entry point. Wires `Spectre.Console.Cli` (`CommandApp<RunCommand>`) with an animated spinner, then delegates to `ChangeMonitorApplication.Run()`.

### [`GCNet/ChangeMonitorApplication.cs`](GCNet/ChangeMonitorApplication.cs)

Top-level orchestrator:
- Resolves `baseDn` from RootDSE when not explicitly supplied.
- Calls `BaselineSnapshotLoader` to pre-populate the baseline dictionary.
- Creates `ChangeProcessingPipeline`, `EventFileWriter`, and the notification loop task.
- Wires `OnBeforeReconnect` → `LdapConnectionFactory.ResetCachedDomainController()` so each reconnect triggers fresh DC discovery.
- Tracks two live metrics — LDAP notifications received and JSON files written — and refreshes the Spectre status line.
- Performs cooperative shutdown: cancels the `CancellationToken`, then waits up to 5 s for each task.

### [`GCNet/LdapNotificationLoopService.cs`](GCNet/LdapNotificationLoopService.cs)

Core LDAP loop. Opens a persistent search with `DirectoryNotificationControl`, blocks until the next entry arrives (`GetResponse`), parses it, and enqueues a `ChangeEvent`. On any recoverable LDAP error:
1. Calls `context.OnBeforeReconnect` (clears DC cache).
2. Waits with **capped exponential back-off + ±20 % jitter**: `2^(min(attempt,6)−1) × (1 + rand(0, 0.2))` seconds.
3. Reopens the connection and re-subscribes.

`IsRecoverableNotificationException` decides which exception types warrant a retry.

### [`GCNet/LdapConnectionFactory.cs`](GCNet/LdapConnectionFactory.cs)

Thread-safe DC caching:
- First call → `DomainControllerSelector.SelectBestDomainController()` → store result.
- Subsequent calls → reuse cached DC name.
- `ResetCachedDomainController()` nulls the cache; next call rediscovers.

Connection settings: `AuthType.Negotiate`, protocol version 3, `AutoReconnect=true`, 1-hour timeout, referral chasing disabled. Keep-alive options (`PingKeepAliveTimeout`, `PingWaitTimeout`, `TcpKeepAlive`) are applied reflectively. Server certificate validation is **intentionally disabled**.

### [`GCNet/DomainControllerSelector.cs`](GCNet/DomainControllerSelector.cs)

Auto-discovery algorithm:
1. Enumerate DCs via `System.DirectoryServices.ActiveDirectory`.
2. Probe each DC in parallel (bind + rootDSE query, 3 s timeout); cache results for 2 minutes.
3. If `--prefer-site-local`, filter to the local AD site first; fall back to all healthy DCs.
4. Return the first healthy DC; maintain a round-robin fallback list for reconnects.

### [`GCNet/ChangeProcessingPipeline.cs`](GCNet/ChangeProcessingPipeline.cs)

Producer-consumer pipeline with two `BlockingCollection<T>` queues (`Incoming` → `Outgoing`). Worker thread per event:
1. If `--tracked-attributes` is set, serialize each tracked attribute to canonical JSON and compare against the baseline. Drop events where none changed.
2. Optionally call `MetadataEnricher`.
3. Update the baseline entry with new values.
4. Enqueue `Dictionary<string, object>` to `Outgoing`.

Canonical comparison uses `Newtonsoft.Json.Linq.JToken` for a stable, type-agnostic string representation.

### [`GCNet/BaselineSnapshotLoader.cs`](GCNet/BaselineSnapshotLoader.cs)

Before entering the notification loop, performs an LDAP `SearchRequest` (`Subtree`, tracked attributes only) and stores each result as a `BaselineEntry` in the shared `ConcurrentDictionary`. Progress is shown on the spinner.

### [`GCNet/LdapEntryParser.cs`](GCNet/LdapEntryParser.cs)

Converts `SearchResultEntry` → `ChangeEvent`. Extracts `objectGUID`, `distinguishedName`, and all attribute values. Binary attributes are hex-encoded or decoded to `Guid`/`string` as appropriate.

### [`GCNet/EventFileWriter.cs`](GCNet/EventFileWriter.cs)

Writes one JSON file per event. File name: `{yyyyMMdd_HHmmss_fff}_{sanitized-dn}.json`, DN component capped at 180 chars. Uses `StreamWriter` + `JsonTextWriter` (indented, UTF-8 without BOM). A lock serialises concurrent writes.

### [`GCNet/MetadataEnricher.cs`](GCNet/MetadataEnricher.cs)

Queries `msDS-ReplAttributeMetaData` for a given DN and returns a `JArray` with `attributeName`, `version`, `lastOriginatingChange`, `originatingDsaDN` per attribute.

### [`GCNet/CanonicalValueHelper.cs`](GCNet/CanonicalValueHelper.cs)

Produces a stable JSON string from any attribute value — handles `null`, `string`, `string[]`, `byte[]`, and arbitrary objects via `JToken.FromObject`.

### [`GCNet/ObjectKeyBuilder.cs`](GCNet/ObjectKeyBuilder.cs)

Baseline dictionary key: `objectGuid.ToString("D")` when available, `dn:{distinguishedName}` as fallback.

### [`GCNet/AppConsole.cs`](GCNet/AppConsole.cs)

Thin logging wrapper. Prepends a UTC ISO-8601 timestamp and writes to `Console.Error` to keep log output separate from any stdout piping. `WriteException` adds structured exception details.

### [`GCNet/MonitoringLifecycleService.cs`](GCNet/MonitoringLifecycleService.cs)

Encapsulates `CancellationTokenSource` and Ctrl-C / SIGTERM handler. `WaitForStopSignal()` blocks until the user presses Ctrl-C. `WaitForTask`/`WaitForTasks` wrap `Task.Wait` with a timeout and log without re-throwing.

### [`GCNet/PipelineMetrics.cs`](GCNet/PipelineMetrics.cs)

`Interlocked`-based counters for notifications received and JSON files written, used by the status display.

---

## Data Structures

### `ChangeEvent`

```csharp
sealed class ChangeEvent
{
    Guid?                       ObjectGuid         // objectGUID from LDAP
    string                      DistinguishedName  // DN of the changed object
    SearchResultEntry           Entry              // raw LDAP entry (used for parsing)
    Dictionary<string, object>  Properties         // parsed attribute bag → written to JSON
}
```

### `BaselineEntry`

```csharp
sealed class BaselineEntry
{
    string                      DistinguishedName
    Dictionary<string, string>  Attributes   // canonical JSON strings per tracked attribute
}
```

Baseline dictionary key: `objectGuid.ToString("D")` or `dn:{distinguishedName}`.

### JSON Event File

One file per qualified event. Top-level keys mirror LDAP attribute names; additional keys:

| Key | Type | Description |
|---|---|---|
| `distinguishedName` | string | DN of the changed object |
| `objectGuid` | string (GUID format) | Stable object identity |
| `eventTimestamp` | ISO-8601 string | Time the event was written |
| `<attr>_old` | any | Previous value (tracked mode only) |
| `<attr>_new` | any | New value (tracked mode only) |
| `msdsReplAttributeMetaData` | array | Replication metadata (only with `--enrich-metadata`) |

---

## Build & Publish

```powershell
# Debug build
dotnet build GetChanges.sln -c Debug

# Release — single self-contained exe (no .NET runtime required on target)
dotnet publish GCNet/GetChanges.csproj -c Release -r win-x64 `
  /p:SelfContained=true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
# Output: GCNet\bin\Release\net10.0-windows\win-x64\publish\GCNet.exe
```

---

## Security Notes

- **Certificate validation is disabled** in `LdapConnectionFactory.cs`. Suitable for trusted internal AD networks; enable it for stricter environments.
- Output JSON files contain AD attribute data — restrict ACLs on the output directory accordingly.
- The tool authenticates as the current user via Kerberos (`AuthType.Negotiate`). No passwords are stored or logged.
- High-traffic domains may generate many files; plan disk space and implement log rotation externally.

---

## Project Dependencies

| Package | Version | Purpose |
|---|---|---|
| `Newtonsoft.Json` | 13.0.4 | JSON serialisation |
| `Spectre.Console` | 0.55.2 | Rich terminal spinner and status display |
| `Spectre.Console.Cli` | 0.55.0 | Declarative CLI argument parsing |
| `SharpHoundCommonLib` | project ref (submodule) | LDAP helpers, RPC support types |

`SharpHoundCommon` submodule HEAD: `28512735`.
