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
    change that fails with `0x80070547`. The uncovered path should not be
    assumed to be the safer one on the strength of having had fewer bugs
    found in it.
  - The password change itself does not succeed on the explicit-bind path.
    That is an open issue rather than a property of the harness; see
    [The AD password change on the explicit-bind path](#the-ad-password-change-on-the-explicit-bind-path)
    below for what has been ruled out.
- The LDAP smoke test relies on MokAPI's LDAP fixture support. Swap in
  `osixia/openldap` if you need a more realistic password-change path
  (Modify with `userPassword` works against both; the AD-style
  `unicodePwd` delete/add flow only works against a real AD).

## The AD password change on the explicit-bind path

**Status: open.** Against the containerised Samba AD DC, with
`UseAutomaticContext: false` and explicit service-account credentials, reads
work and the password change does not. `SDSUtils.ChangePassword` — the ADSI
call behind `UserPrincipal.ChangePassword` — fails.

**The exact error, captured once the group legs stopped blocking Test 1:**

```
DirectoryUnavailableException: The directory service could not complete the password change request
 ---> PrincipalOperationException: Configuration information could not be read from the
      domain controller, either because the machine is unavailable, or access has been
      denied. (0x80070547)
   at System.DirectoryServices.AccountManagement.SDSUtils.ChangePassword(DirectoryEntry de, ...)
   at System.DirectoryServices.AccountManagement.ADStoreCtx.ChangePassword(...)
   at System.DirectoryServices.AccountManagement.AuthenticablePrincipal.ChangePassword(...)
```

`0x80070547` is `ERROR_CANT_ACCESS_DOMAIN_INFO` (1351). Earlier notes recorded
this as `E_ACCESSDENIED`; that was from a less precise capture, and this stack is
the one to work from.

**The distinction matters, and it is a lead rather than a detail.** The failure is
not "permission denied on the password write" — it is ADSI being unable to read
**configuration information** from the DC. That is the Configuration naming
context, and it is the same thing `Forest.GetForest()` needs and cannot get on
this runner. Two failures previously treated as unrelated may share one root
cause: a machine that is not domain-joined, reaching the Configuration NC over an
explicit bind. Anyone resuming this should test that hypothesis before any
transport or credential theory — those are already ruled out below.

This is recorded here because the obvious explanations have been tested and
are not the cause. Anyone picking it up should start after this list, not
before it.

### What has been ruled out, with evidence

| Hypothesis | How it was tested | Result |
| ---------- | ----------------- | ------ |
| Unreachable transports causing ADSI to time out through its transport list | Published 88, 464, 636, 3268 and 3269 in addition to 389; all five confirmed reachable from the runner | Not the cause. The request still failed, in 11.18s against 11.4s before — so the duration was never port timeouts either |
| The DC's certificate not being trusted, so SSL is unavailable | Extracted the DC's CA and installed it in the runner's trusted root store; probed with `LdapConnection` | Not the cause. LDAPS binds to both `example.com:636` and `dc.example.com:636` succeed |
| An unprotected channel, with the DC refusing a password change over it | Read the provider's own EventId 108 | Not the cause. The context is established over sign-and-seal, with no SSL fallback — the channel is signed and encrypted |
| Kerberos being unavailable, leaving a weaker authentication than the operation needs | Routed the runner to the podman bridge so the container's own address was reachable, then bound with `AuthType.Kerberos` explicitly so NTLM could not satisfy it | Not the cause of the change failing, and not fixable here. Reachability was fine (`10.88.0.2:389` and `:88` both reachable) and the bind still failed with `"A local error occurred."` — the client failing before the wire, because a machine that is not domain-joined has no `EXAMPLE.COM` realm mapping |
| The pinned `LdapPort` keeping ADSI's SSL transport off 636 | Set `LdapPort: 636` in `appsettings.ADTest.json` | Not the cause, and actively worse. See below |

### The `LdapPort: 636` result, and what it exposed

The idea was that `IADsUser::ChangePassword` tries LDAP over SSL among its
transports, and that a `DirectoryEntry` carrying `LDAP://dc.example.com:389/…`
never gives it an SSL connection to use. Pinning 636 should have made the
provider's existing sealed→SSL fallback hand it one.

It never got that far. With 636 configured, **both** channels were refused and
context acquisition failed outright:

```
sealed  (Negotiate|Signing|Sealing) on dc.example.com:636
  COMException (0x8007203A): The server is not operational.
SSL     (Negotiate|SecureSocketLayer) on dc.example.com:636
  DirectoryServicesCOMException (0x80072028): A more secure authentication
  method is required for this server.
```

EventId 108 never fired — no channel was ever established — and the run died at
the first assertion, the `minPwdLength` read that passes on 389. The port is
back to 389 and this hypothesis is closed.

The second error is the part worth keeping. **That was the first time the SSL
fallback in `AcquirePrincipalContext` has ever been exercised**, because the
sealed bind on 389 has always succeeded and short-circuited it — and it failed.
So the fallback that the code advertises as its safety net is, against this DC,
unproven at best. Note the contrast: a raw `LdapConnection` with SSL to the same
host and port succeeds from the same runner in the same job. The difference is
ADSI, not the network and not the certificate.

Two things follow, and they are separable:

- **The fallback needs its own coverage.** It is currently reached only when the
  primary channel fails, which in CI is never. Whatever is wrong with it is
  invisible from a green run.
- **`0x80072028` is `LDAP_STRONG_AUTH_REQUIRED`.** Samba's
  `ldap server require strong auth` refusing the bind that ADSI actually sent is
  the first thing to check — which means capturing what ADSI sent, rather than
  reasoning about what it should have sent. This investigation has twice
  produced a fix whose stated rationale turned out to be wrong, so the next step
  is a packet capture or a Samba-side log, not another configuration guess.

### What the smoke test asserts about it

Test 1 asserts the password change **succeeds**, and it currently fails. The
assertion has deliberately not been weakened to match the behaviour: it
describes what the provider is supposed to do, and a failing assertion is the
correct report of an open defect. Do not relax it to get a green run.

Test 1 is now the **only** failing assertion in the AD smoke test. It spent a
long time unreachable: the group legs run before it, and Leg A's non-member
assertion could not be answered while membership resolution depended on
`Forest.GetForest()`. Since the move to security-groups-only, Legs A–D pass and
Test 1 executes, which is how the stack above was finally captured.

The legs' own "must be permitted" assertions are unaffected by the change failing.
They check that the account got **past the group check**, not that the password
was written, so they treat anything other than `UserNotFound` (3),
`InvalidCredentials` (4) or `ChangeNotPermitted` (6) as permitted. Their trailing
`restore` calls do fail — the password was never changed, so restoring it with the
new one cannot authenticate — and that is why `ERROR_LOGON_FAILURE (1326)` appears
in the log alongside each of them. It is expected noise from `|| true` cleanup, not
a second defect.
