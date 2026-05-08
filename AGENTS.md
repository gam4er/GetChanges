# Repository Guidelines

## Project Structure & Module Organization

- `GetChanges.sln` is the solution entry point.
- `GCNet/` is the primary console app (AD LDAP change monitor). Key sources live directly under `GCNet/` (for example `GCNet/GCNet.cs`, `GCNet/ChangeProcessingPipeline.cs`).
- `SharpHoundCommon/` is a Git submodule that provides shared libraries and has its own `src/` and `test/` trees. Current HEAD: `28512735`.
- The `packages/` directory is a leftover from the old `packages.config` era and is no longer used by the SDK-style project.

## Build, Test, and Development Commands

- Build (Debug): `dotnet build GetChanges.sln -c Debug`
- Build (Release): `dotnet build GetChanges.sln -c Release`
- Publish single-file self-contained executable (replaces Costura.Fody):
  ```
  dotnet publish GCNet/GetChanges.csproj -c Release -r win-x64 \
    /p:SelfContained=true /p:PublishSingleFile=true /p:IncludeNativeLibrariesForSelfExtract=true
  ```
- Run after build: `GCNet/bin/Debug/net10.0-windows/GCNet.exe --tracked-attributes userAccountControl,pwdLastSet,badPasswordTime,mail`
- This repo targets **net10.0-windows** (`GCNet/GetChanges.csproj`). `dotnet` SDK 10.x is required.
- There is no top-level test runner in this repo; unit tests live in the `SharpHoundCommon` submodule.

## Key Dependencies (GCNet)

| Package | Version | Purpose |
|---|---|---|
| Newtonsoft.Json | 13.0.4 | JSON serialisation of change events |
| Spectre.Console | 0.55.2 | Rich terminal UI / status display |
| Spectre.Console.Cli | 0.55.0 | Declarative command-line parsing |
| SharpHoundCommonLib | project ref | LDAP helpers from SharpHoundCommon submodule |

## Coding Style & Naming Conventions

- C# files use standard .NET conventions: `PascalCase` for types/methods, `camelCase` for locals and parameters.
- Indentation follows the existing project defaults (4 spaces; no tabs).
- Keep new files alongside related components in `GCNet/` unless they belong to the submodule.
- SDK-style csproj — no `App.config`, `packages.config`, or `FodyWeavers.xml` (all removed during migration).

## Testing Guidelines

- No first-party tests are defined at the root solution level.
- If you modify `SharpHoundCommon/`, run its tests from that submodule (see `SharpHoundCommon/README.md`).

## Commit & Pull Request Guidelines

- Commit messages follow an imperative style; short scopes like `docs:` appear in history (examples: `docs: ...`, `Refactor ...`, `Fixes`).
- PRs typically include a concise summary and the test status (or a note when tests are not run).
- If a change touches the submodule, call it out explicitly in the PR description.

## Security & Configuration Tips

- GCNet writes potentially sensitive directory data to per-event JSON files. Treat output files as sensitive artifacts.
- LDAP connections in `GCNet/LdapConnectionFactory.cs` intentionally disable server certificate validation (`VerifyServerCertificate` returns `false`); review this if you need stricter security postures.
