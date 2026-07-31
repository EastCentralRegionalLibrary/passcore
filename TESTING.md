# Testing PassCore

PassCore is exercised by three layers of automated tests:

| Layer | Project(s) | Runner |
| ----- | ---------- | ------ |
| Backend unit tests | `tests/Unosquare.PassCore.Common.Tests`, `tests/Unosquare.PassCore.PasswordProvider.Debug.Tests`, `tests/Zyborg.PassCore.PasswordProvider.LDAP.Tests`, `tests/PwnedPasswordsSearch.Tests` | xUnit (`dotnet test`) |
| LDAP integration smoke test | `tests/mokapi` (MokAPI LDAP fixtures) + `.github/workflows/ldap-provider-smoke-test.yml` | curl + `jq` against a running container |
| Front-end E2E | `src/Unosquare.PassCore.Web/ClientApp/tests/e2e` | Playwright (Chromium, Firefox) against the Debug provider |

## Prerequisites

- .NET 8.0 SDK
- Node.js 22.x + npm
- (Optional, for the LDAP smoke test) Docker

## Running the backend unit tests

From the repository root:

```bash
dotnet test
```

This builds and runs every test project in the solution. Coverage spans:

- `PasswordChangeProviderBase` — policy evaluation order, validation short-circuit, exception → `ApiErrorItem` mapping, cancellation propagation.
- All five built-in policies (`Length`, `Complexity`, `Distance`, `GroupMembership`, `Pwned`).
- `DebugPasswordChangeProvider` — every legacy forced-error mapping, configured `ForcedErrors` precedence, domain-stripping, `SimulateLatencyMs`, `DefaultErrorCode`.
- `LdapPasswordChangeProvider` constructor / option validation.
- `PwnedSearch` against a stub `HttpMessageHandler`: happy path, missing-suffix case, non-success HTTP, and transport failure.

## Front-end E2E tests (Playwright)

The E2E suite drives the SPA against a running backend that uses the
`DebugPasswordChangeProvider`. The provider maps each magic username
(`error`, `changeNotPermitted`, `invalidCredentials`, `userNotFound`,
`ldapProblem`, `complexPassword`, …) to a specific `ApiErrorCode`, so
the front-end exercises every alert / error branch without needing an
AD or LDAP backend.

```bash
# 1. Build the backend in Debug mode (Debug provider is selected automatically).
dotnet build src/Unosquare.PassCore.Web/Unosquare.PassCore.Web.csproj \
  -c Debug -p:PASSCORE_PROVIDER=DEBUG

# 2. Install front-end dependencies + Playwright browsers
cd src/Unosquare.PassCore.Web/ClientApp
npm ci
npx playwright install --with-deps chromium firefox

# 3. In one terminal, run the backend
cd ../../..
ASPNETCORE_ENVIRONMENT=Test \
ASPNETCORE_URLS=http://localhost:5000 \
  dotnet run --no-build \
    --project src/Unosquare.PassCore.Web/Unosquare.PassCore.Web.csproj \
    -c Debug -p:PASSCORE_PROVIDER=DEBUG

# 4. In another terminal, run the tests
cd src/Unosquare.PassCore.Web/ClientApp
npx playwright test
```

## LDAP smoke test

The `ldap-provider-smoke-test.yml` workflow brings up a
[MokAPI](https://mokapi.io/) LDAP server populated from
`tests/mokapi/users.ldif`, starts PassCore with the LDAP provider
against it, and exercises the API end-to-end:

- Happy path (`alloweduser` in `AllowedGroup`).
- Invalid current password → `InvalidCredentials`.
- Unknown user → `InvalidCredentials` (because `HideUserNotFound` defaults to true).
- User in `RestrictedGroup` → `ChangeNotPermitted`.
- User not in any allowed group → `ChangeNotPermitted`.
- LDAP outage → `LdapProblem` (or `InvalidCredentials`).

Run it manually with the `workflow_dispatch` trigger.

## Continuous integration

| Workflow | Purpose |
| -------- | ------- |
| `ci-testing.yml` | Backend unit tests + Playwright E2E against the Debug provider. |
| `ldap-provider-smoke-test.yml` | LDAP provider end-to-end against MokAPI. |
| `build_docker_validate.yml` | Hadolint + Docker image build + HTTP probe. |
| `build_windows.yml` | Windows binaries (AD provider) on tag pushes. |
| `build-sonar.yml` / `codeql.yml` | Static analysis. |

Playwright reports and `.trx` test results are uploaded as workflow
artifacts when a job fails.

## Known limitations

- Playwright runs Chromium and Firefox in CI. Add a WebKit project to
  `playwright.config.ts` if additional cross-browser coverage is desired.
- The AD provider smoke test (`ad-provider-smoke-test.yml`) runs against a
  Samba AD DC in a container, so the provider is no longer covered only by the
  Windows build job. What it does and does not reach is worth stating
  precisely, because the difference is a configuration the runner cannot adopt:

  - The runner is not domain-joined, so `appsettings.ADTest.json` must set
    `UseAutomaticContext: false`. Production deployments normally run it
    **true**, and the two take different paths through
    `AcquirePrincipalContext`.
  - **Covered**, and configuration-independent — the same code runs either
    way: provider logic, error routing and disclosure posture, policy
    evaluation order, group membership resolution, and the `minPwdLength`
    read.
  - **Not covered anywhere**: context construction and channel selection on
    the automatic-context path, which calls
    `new PrincipalContext(ContextType.Domain)` with no server, credentials or
    options. No job exercises it.
  - The explicit-credentials path that *is* covered has already been found
    broken twice — the ADSI path defect behind `minPwdLength`, and a password
    change that fails with `E_ACCESSDENIED`. The uncovered path should not be
    assumed to be the safer one on the strength of having had fewer bugs
    found in it.
- The LDAP smoke test relies on MokAPI's LDAP fixture support. Swap in
  `osixia/openldap` if you need a more realistic password-change path
  (Modify with `userPassword` works against both; the AD-style
  `unicodePwd` delete/add flow only works against a real AD).
