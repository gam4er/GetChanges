# Repository Guidelines (framework branch)

## Branch Context

- **Branch:** `framework` — long-lived parallel track of `devel`, kept on **.NET Framework 4.8** for environments that cannot run .NET 10.
- For the modern .NET 10 variant work on the `devel` branch instead.

## Project Structure & Module Organization

- `GetChanges.sln` is the solution entry point.
- `GCNet/` is the primary console app (AD LDAP change monitor). After the framework-branch refactor, sources are grouped by responsibility:
  - `GCNet/Hosting/` — entry point, CLI options, top-level orchestrator and process lifecycle.
  - `GCNet/Ldap/` — connection factory, DC discovery, persistent-search loop, entry parsing, schema/metadata helpers.
  - `GCNet/Pipeline/` — baseline snapshot loader, change pipeline, canonical value comparison, pipeline metrics.
  - `GCNet/Models/` — DTOs (`ChangeEvent`, `BaselineEntry`).
  - `GCNet/Output/` — JSON event file writer.
- `SerializeToJSONLikeSharpHound/` — small helper tool for serialization compatibility experiments.
- `SharpHoundCommon/` — git submodule providing shared libraries (multi-target, `net472` consumed here).
- `packages/` — restored NuGet packages for classic `packages.config` projects.

## Build, Test, and Development Commands

A **VS 2022 Developer PowerShell** (or Developer Command Prompt) is required so that `msbuild` is on PATH. From a regular shell run:

```powershell
& 'C:\Program Files\Microsoft Visual Studio\2022\Professional\Common7\Tools\Launch-VsDevShell.ps1' -SkipAutomaticLocation
```

GCNet uses `packages.config`, which `msbuild /t:Restore` does **not** restore. Use `nuget.exe`:

```powershell
# one-time bootstrap if nuget.exe is missing
Invoke-WebRequest https://dist.nuget.org/win-x86-commandline/latest/nuget.exe `
  -OutFile "$env:USERPROFILE\.nuget\nuget.exe"

# restore + build
& "$env:USERPROFILE\.nuget\nuget.exe" restore GetChanges.sln
msbuild GetChanges.sln /p:Configuration=Release /v:minimal
```

Run after build:

```powershell
GCNet\bin\Release\GCNet.exe --base-dn "DC=corp,DC=local"
GCNet\bin\Release\GCNet.exe --help
```

This branch targets **.NET Framework 4.8** (`GCNet/GetChanges.csproj` → `<TargetFrameworkVersion>v4.8</TargetFrameworkVersion>`) and the `SharpHoundCommon` submodule is consumed as **net472**.

There is no top-level test runner. Unit tests live under the `SharpHoundCommon` submodule.

## Coding Style & Naming Conventions

- C# files use standard .NET conventions: `PascalCase` for types/methods, `camelCase` for locals and parameters.
- Indentation: 4 spaces, no tabs (matches existing files).
- Keep `namespace GCNet` flat — folders express grouping, not nested namespaces. This minimises `using` churn when files move.
- New files must be registered explicitly in `GCNet/GetChanges.csproj` under the `<Compile Include="...">` item group with the correct subfolder path.
- Stay compatible with C# language features available on .NET Framework 4.8 / VS 2022 — avoid `Random.Shared`, file-scoped namespaces, raw string literals, and other newer-runtime-only APIs.

## Testing Guidelines

- No first-party tests are defined at the root solution level.
- If you modify `SharpHoundCommon/`, run its tests from that submodule (see `SharpHoundCommon/README.md`).

## Required-to-update Files

When making non-trivial changes to GCNet, update the following alongside the code:

- `AGENTS.md` (this file) — keep build/run instructions accurate.
- `README.md` — update architecture description and deep links if file paths or line numbers shift materially. **`README.md` is the source of truth.**
- `README_rus.md` — Russian translation of `README.md`. Whenever `README.md` is edited, mirror the same changes (sections, deep links, line numbers, code blocks) into `README_rus.md` in the same commit. Do not let the two files drift.

## Commit & Pull Request Guidelines

- Commit messages follow an imperative style; short scopes appear in history (examples: `docs: ...`, `Refactor ...`, `Fixes`).
- PRs typically include a concise summary and the test/build status.
- If a change touches the submodule, call it out explicitly in the PR description and ensure the submodule SHA is committed.

## Security & Configuration Tips

- GCNet writes potentially sensitive directory data to per-event JSON files. Treat output files as sensitive artifacts and rotate / scope access accordingly.
- LDAP connections in `GCNet/Ldap/LdapConnectionFactory.cs` intentionally disable certificate validation (`VerifyServerCertificate => false`) for typical AD lab/internal deployments. Review and replace with proper validation for production / external deployments.
