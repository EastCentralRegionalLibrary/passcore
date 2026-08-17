# Build environment notes

Practical notes for building and testing PassCore in a fresh Linux container. Everything
here was verified by running it, not inferred. `CONTRIBUTING.md` covers process and code of
conduct; this file covers only getting a build and the tests to run.

## Quickstart

```bash
# 1. .NET SDK is NOT preinstalled and NOT on PATH. Install it (~1 min):
curl -sSL https://dot.net/v1/dotnet-install.sh -o /tmp/dotnet-install.sh
bash /tmp/dotnet-install.sh --channel 8.0 --install-dir "$HOME/.dotnet"
export PATH="$HOME/.dotnet:$PATH"          # needed in EVERY shell; nothing sets it for you

# 2. Full test suite (expect 18 / 374 / 24 / 426 = 842, zero failures)
dotnet test Unosquare.PassCore.sln -c Release

# 3. Everything, including the Windows-only AD provider, on Linux
dotnet build Unosquare.PassCore.sln -c Release
```

`-sSL` matters on step 1: `https://dot.net/v1/dotnet-install.sh` answers **301**, so `curl`
without `-L` writes an empty file.

## Target frameworks: one per project, and never host-dependent

Every project targets `net8.0`. Two exceptions, both of which pin their own framework:

| Project | Framework |
| --- | --- |
| `Unosquare.PassCore.PasswordProvider` (AD) | `net8.0-windows`, always |
| `Unosquare.PassCore.Web` | follows `PASSCORE_PROVIDER`: `net8.0-windows` for `AD`, else `net8.0` |

Nothing multi-targets, so ordinary commands work: `dotnet build` on the solution succeeds on
Linux, `dotnet publish` needs no `-f`, and the AD provider compiles without special flags.

**If you pin a framework in a project, clear the plural at the same time:**

```xml
<TargetFrameworks />
<TargetFramework>net8.0-windows</TargetFramework>
```

NuGet restore reads the **plural** `TargetFrameworks`, which `Directory.Build.props` sets. Setting
only the singular property leaves restore producing assets for the inherited framework while the
build asks for yours, and it fails with:

```
NETSDK1005: Assets file '.../project.assets.json' doesn't have a target for 'net8.0-windows'.
```

The AD provider carried exactly that bug. It was masked on Windows, because the props used to
expand the plural to `net8.0;net8.0-windows` there, and on Linux the workaround was to pass
`-p:TargetFrameworks=net8.0-windows` by hand.

That host-varying plural is gone, and with it: publish refusing to run without `-f`
(`NETSDK1129`), solution builds failing on Linux, three projects being compiled twice on Windows,
and the frontend targets in the Web project running once per inner build — in parallel on Windows,
where two concurrent `npm ci` processes corrupted `node_modules` and failed the Sonar job.

The plural/singular split still matters for **test projects**, in the other direction.
`ci-testing.yml` guards against `dotnet test` reporting "No test is available", because a test
project declaring the singular `TargetFramework` skips the package `.props` imports, the xunit
VSTest adapter never reaches the output directory, and **`dotnet test` then exits 0 having run
zero assertions**. If you add a test project, declare `TargetFrameworks` (plural).

### `EnableWindowsTargeting` is not needed

Guides suggest `-p:EnableWindowsTargeting=true` for building Windows TFMs on Linux. This repo does
not need it — verified with a clean `obj/`+`bin/` build. It is for Windows Desktop (WPF/WinForms)
workloads; this project's Windows dependency is `System.DirectoryServices`, an ordinary NuGet
package. Passing it is harmless but noise.

## `WINDOWS` follows the target framework, never the build host

Every type in `Unosquare.PassCore.PasswordProvider` sits inside `#if WINDOWS`, which makes this
worth stating plainly: **the AD provider compiles fully on Linux.**

The SDK implicitly defines the platform symbol for any platform-specific TFM, so `net8.0-windows`
yields `WINDOWS`, `WINDOWS7_0` and `WINDOWS7_0_OR_GREATER` on every host. Two consequences that
are easy to get wrong:

- **`$(DefineConstants)` never contains `WINDOWS`.** The SDK merges implicit constants straight
  into the `Csc` invocation. Read the property mid-build and you get
  `TRACE;RELEASE;NET;NET8_0;NETCOREAPP`. Any MSBuild guard asserting `WINDOWS` is in
  `$(DefineConstants)` therefore fires on *every* build. Check the compiler command line instead
  (`-v:n`, grep `/define:`).
- **`$(TargetPlatformIdentifier)` is empty in the project body.** It is set by SDK targets imported
  *after* the body, so a `PropertyGroup Condition` on it silently never fires.

Both dead ends are recorded in a comment in
`src/Unosquare.PassCore.PasswordProvider/Unosquare.PassCore.PasswordProvider.csproj`.

## Provider selection

The Web project picks its password provider at compile time via `PASSCORE_PROVIDER`, which selects
the target framework, the referenced backend project, and a matching `PASSCORE_*_PROVIDER` constant:

| Value | Provider | Notes |
| --- | --- | --- |
| `AD` | `Unosquare.PassCore.PasswordProvider` | Builds the Web project as `net8.0-windows` |
| `LDAP` | `Zyborg.PassCore.PasswordProvider.LDAP` | Cross-platform; **the default when unset** |
| `DEBUG` | `Unosquare.PassCore.PasswordProvider.Debug` | What CI uses for backend + E2E runs |

The provider decides the framework, not the reverse. `AD` is therefore never implied — ask for it
explicitly, including in an IDE, or you get an LDAP build.

```bash
# Backend as CI builds it
dotnet build src/Unosquare.PassCore.Web/Unosquare.PassCore.Web.csproj \
  -c Debug -p:PASSCORE_PROVIDER=DEBUG
```

## Tests

Four suites; these counts are the regression baseline:

| Assembly | Tests |
| --- | --- |
| `Unosquare.PassCore.Common.Tests` | 357 |
| `Zyborg.PassCore.PasswordProvider.LDAP.Tests` | 386 |
| `Unosquare.PassCore.PasswordProvider.Debug.Tests` | 24 |
| `PwnedPasswordsSearch.Tests` | 4 |

- **Parse `Total:`, not `Total tests:`.** Verified against SDK 8.0.423: the per-assembly summary
  line is `Passed!  - Failed: 0, Passed: 357, Skipped: 0, Total: 357, Duration: … - <assembly>.dll`.
  There is no `Total tests:` line anywhere in the output, so grepping for it matches nothing and
  yields a silently empty result — which reads identically before and after a change, so a
  comparison against it always "passes".
- **Some tests read repository source from disk.** The audit tests (logging conventions, shipped
  config, hardened defaults) use `Unosquare.PassCore.Testing.RepositorySource`, which walks up from
  `AppContext.BaseDirectory` looking for `Unosquare.PassCore.sln`. They must run from a source
  checkout, not a published output, and they see files on disk rather than compiled behaviour — so
  editing a format string or a comment can change an audit result.
- Confirm a specific audit actually ran rather than assuming; passing tests are not listed at
  default verbosity:
  ```bash
  dotnet test tests/Unosquare.PassCore.Common.Tests/Unosquare.PassCore.Common.Tests.csproj \
    -c Release --filter 'FullyQualifiedName~LoggingConventionAuditTests' \
    --logger 'console;verbosity=normal'
  ```

### Logging conventions

Log statements go through `LoggerMessage.Define` delegates with allocated EventIds, and
`LoggingConventionAuditTests` enforces this repo-wide: unique EventIds, no ad-hoc `Logger.Log*`
calls in providers, and one format-string placeholder **occurrence** per type argument. `Define`
counts occurrences, not distinct names, so repeating a placeholder still requires an extra type
argument. Because these are `static readonly` fields, a mismatch is a type-initialization failure
at first use, not a compile error.

## Frontend

Node 22 and npm are preinstalled (`v22.22.2` / `10.9.7`), matching CI. The Playwright E2E suite
lives in `src/Unosquare.PassCore.Web/ClientApp`.

Browsers are pre-provisioned at `/opt/pw-browsers` (`PLAYWRIGHT_BROWSERS_PATH` is already set) —
**do not run `playwright install`**. Note that only Chromium is present locally; CI installs
Chromium *and* Firefox, so a Firefox-only failure will not reproduce here.

## CI matrix

Nine workflows. What runs on every pull request:

| Workflow | Runner | Purpose |
| --- | --- | --- |
| `ci-testing.yml` | ubuntu | Backend build (`PASSCORE_PROVIDER=DEBUG`), the four unit suites, Playwright E2E |
| `ad-provider-smoke-test.yml` | windows | Publishes with `PASSCORE_PROVIDER=AD` and drives real password changes against a live directory |
| `ldap-provider-smoke-test.yml` | ubuntu | LDAP provider smoke test |
| `ldap-samba-smoke-test.yml` | ubuntu | LDAP against Samba AD |
| `build_docker_validate.yml` | ubuntu | Docker build validation |
| `build-sonar.yml` | windows | Static analysis |
| `codeql.yml` | ubuntu | CodeQL (also scheduled) |

Tag/dispatch only: `build_windows.yml`, `build_docker.yml`.

Worth knowing before adding CI: **the AD provider is already compiled *and executed* on every PR**
by `ad-provider-smoke-test.yml`, which is ungated. A Linux compile step for it would be redundant
coverage, not new coverage.

## Environment quirks

- **Nothing puts `dotnet` on PATH.** Export it per shell; a `cd` in a compound command can also
  trigger a permission prompt, so prefer absolute paths.
- **No `global.json`**, so the SDK floats to whatever is installed. Verified against 8.0.423 with
  runtimes 8.0.29.
- **Outbound HTTPS goes through a proxy** with a CA bundle at `/root/.ccr/ca-bundle.crt`. On a TLS
  or 403/405/407 failure, read `/root/.ccr/README.md`; never disable TLS verification or unset
  `HTTPS_PROXY`.
- **Writable disk is a fixed allowance**, so `df` misleads: `Avail` at 0 with low `Used` means the
  allowance is spent. Deleting build artifacts (`obj/`, `bin/`, `node_modules`) frees it
  immediately.
