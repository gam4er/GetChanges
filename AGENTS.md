# Repository Guidelines

## Project Structure & Module Organization

- `GetChanges.sln` is the solution entry point.
- `GCNet/` is the primary console app (AD LDAP change monitor). Key sources live directly under `GCNet/` (for example `GCNet/GCNet.cs`, `GCNet/ChangeProcessingPipeline.cs`).
- `SerializeToJSONLikeSharpHound/` contains a small helper tool for serialization experiments and compatibility.
- `SharpHoundCommon/` is a Git submodule that provides shared libraries and has its own `src/` and `test/` trees.
- `packages/` stores restored NuGet packages for classic `packages.config` projects.

## Build, Test, and Development Commands

- Restore NuGet packages: `nuget restore GetChanges.sln`
- Build the solution (Release): `msbuild GetChanges.sln /p:Configuration=Release`
- Run GCNet after build: `GCNet/bin/Release/GCNet.exe --base-dn "DC=corp,DC=local"`
- This repo targets .NET Framework 4.8 (`GCNet/GCNet.csproj`). Build with Visual Studio or MSBuild from a VS Developer Prompt.
- There is no top-level test runner in this repo; unit tests live in the `SharpHoundCommon` submodule.

## Coding Style & Naming Conventions

- C# files use standard .NET conventions: `PascalCase` for types/methods, `camelCase` for locals and parameters.
- Indentation follows the existing project defaults (4 spaces; no tabs).
- Keep new files alongside related components in `GCNet/` unless they belong to the submodule.

## Testing Guidelines

- No first-party tests are defined at the root solution level.
- If you modify `SharpHoundCommon/`, run its tests from that submodule (see `SharpHoundCommon/README.md`).

## Commit & Pull Request Guidelines

- Commit messages follow an imperative style; short scopes like `docs:` appear in history (examples: `docs: ...`, `Refactor ...`, `Fixes`).
- PRs typically include a concise summary and the test status (or a note when tests are not run).
- If a change touches the submodule, call it out explicitly in the PR description.

## Security & Configuration Tips

- GCNet writes potentially sensitive directory data to per-event JSON files. Treat output files as sensitive artifacts.
- LDAP connections in `GCNet/LDAPSearches.cs` intentionally disable certificate validation; review this if you need stricter security postures.
