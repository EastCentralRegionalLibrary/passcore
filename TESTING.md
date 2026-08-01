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

**The distinction matters.** The failure is not "permission denied on the password
write" — it is ADSI reporting that it could not read **configuration information**
from the DC, i.e. the Configuration naming context.

That looked like it might tie Test 1 to `Forest.GetForest()`, which also needs the
Configuration NC and also fails here. **The probe below refuted that.** The
Configuration NC is readable via `dc.example.com` and fails only via
`example.com` — and `LdapHostnames` is `dc.example.com`, the name that
*succeeds*. Test 1 never names `example.com` at all. So the Configuration NC is
demonstrably readable with these credentials, over this channel, to this host,
and the change still fails claiming it cannot read it.

**Two failures, two causes.** Name resolution explains `Forest.GetForest()`. It
explains nothing about Test 1. Anything suggesting otherwise is wrong and has
been removed rather than softened.

One thing that needs no action: **1351 is not in `Win32ErrorCode`**, so it falls
to the default classification — `Infrastructure`, the same place
`ERROR_ACCESS_DENIED` lands. That is why Test 1 reports code 8 and not something
new, and the wire behaviour is unchanged. The catalog does not need an entry for
it.

### The Configuration NC probe

The AD smoke test reads the Configuration naming context three ways, beside the
existing sealed-bind and LDAPS diagnostics, using ADSI with
`Secure | Signing | Sealing` — the same stack and channel the provider's own
context uses, because a probe on a different channel answers a different
question. The DN comes from rootDSE's `configurationNamingContext` rather than
being constructed, for the same reason `AdsiPath` reads `defaultNamingContext`.

How it was read at the time — **and note the first row's reading was wrong**, see
below:

| `dc.example.com` | `example.com` | Reading as written |
| --- | --- | --- |
| succeeds | fails | ~~Target naming, and both failures share a root cause.~~ Half right: it *is* target naming, but it does not make the causes shared. |
| fails | fails | **Credentials or permissions, not naming.** `EXAMPLE\Administrator` should be able to read this, so the bind itself or Samba's provisioning is the suspect. |
| succeeds | succeeds | **1351 comes from something else.** |

The first row's reading did not survive contact with the result, and the mistake
is worth naming: it assumed the change operation binds by the same name that
failed. It does not. Reading a table row without checking which name the affected
code path actually uses is how a probe designed to settle a question ends up
confirming a prior instead.

#### Result: target naming — which explains `GetForest()`, not Test 1

```
1. rootDSE configurationNamingContext: CN=Configuration,DC=example,DC=com
2. Configuration NC via dc.example.com: SUCCEEDED -- read 'CN=Configuration,DC=example,DC=com'
3. Configuration NC via example.com:   FAILED
     inner: COMException: The user name or password is incorrect.
     inner HRESULT: 0x8007052E
```

The Configuration NC is **readable with these credentials** — so this is not a
permissions problem, and not a Samba provisioning problem. Readability depends
entirely on **which name is used to bind**.

The mechanism behind read 3 is target naming: a signed-and-sealed bind derives its
service principal from the server string it was given, Samba registers
`ldap/dc.example.com` and not `ldap/example.com`, and a name with no SPN behind it
cannot authenticate. `0x8007052E` is 1326, `ERROR_LOGON_FAILURE` — the same code
`Forest.GetForest()` fails with, and for the same reason: `GetForest()` builds its
`DirectoryContext` around the **forest name**, which is exactly the name that has
no SPN. That is the same root cause already documented for `LdapHostnames`, which
was pointed at the DC to work around it.

**This explains `Forest.GetForest()` and not Test 1**, and the distinction is the
most useful thing the probe produced. `LdapHostnames` is `dc.example.com` — read 2,
the one that *succeeded*. The change operation never names `example.com`. So Test 1
runs entirely on the path where the Configuration NC is provably readable, and
still reports that it cannot read it.

Two failures, two causes. Do not fix one expecting the other to move. In
particular, **do not register `ldap/example.com` on the Samba side**: it would
repair `GetForest()` and the `example.com` bind, leave Test 1 untouched, and spend
a fixture change on a dependency the security-groups-only work has already removed
from production.

That made a Kerberos realm mapping the interesting next test. **It was tested and
it does not work — do not retry it.**

#### The ksetup realm mapping, tested and rejected

The reasoning was that with a KDC mapped for `EXAMPLE.COM`, the locator would
resolve the realm to a DC before requesting a ticket, so `ldap/dc.example.com`
would become the SPN in play even when the caller names the realm. **That
reasoning was wrong**, and the run says so plainly.

The mappings themselves took. `ksetup` before and after:

```
BEFORE: Machine is not configured to log on to an external KDC.  Probably a workgroup member
        No user mappings defined.

AFTER:  EXAMPLE.COM:
            kdc = dc.example.com
            kpasswd = dc.example.com
```

And the Kerberos bind genuinely **moved** — it no longer fails before reaching
the wire:

```
before ksetup:  Kerberos bind FAILED: "A local error occurred."
after ksetup:   Kerberos bind FAILED: LdapException: "The supplied credential is invalid."
```

"A local error occurred" is the client failing with no realm mapping. "The
supplied credential is invalid" is an actual authentication exchange being
refused. So the mappings work and Kerberos is live — and it still cannot
authenticate against the realm name.

**Why, and why no mapping can fix it.** A host-to-realm map tells the client
which *realm* a host belongs to. It does not rewrite the *service principal* the
client asks for. Naming `example.com` still requests `ldap/example.com@EXAMPLE.COM`,
and Samba registers `ldap/dc.example.com` — not that. The KDC has no such
principal, so the ticket request fails, which surfaces as invalid credentials.
Note it is the identical error the NTLM sealed bind to `example.com:389` returns:
Kerberos reaches the same wall by the same route.

Nothing downstream moved. The Configuration NC read via `example.com` still
failed with `0x8007052E`, `Forest.GetForest()` still failed with the same error,
and Test 1 still failed. `Domain.GetCurrentDomain()` threw *"Current security
context is not associated with an Active Directory domain or forest"*, which
closes a separate question empirically: **realm mapping is not domain
membership**, so a working Kerberos configuration would still not make
`UseAutomaticContext: true` viable on this runner.

The experiment was reverted. The only remaining ways through are a Samba-side
change registering `ldap/example.com`, or not naming the realm at all — which is
what `LdapHostnames` already does. Neither is reachable from the caller's
configuration for the paths that build their own `DirectoryContext`.

One hazard that did **not** materialise, worth recording since it was expected:
a live-but-failing Kerberos did not make Negotiate stop falling back. The sealed
bind to `dc.example.com` still succeeded, `minPwdLength` still read, and every
group leg returned its usual code. There was no broad red.

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
the first assertion, the `minPwdLength` read that passes on 389.

**Retested, deliberately, and the result is identical.** The first attempt was
discounted because the run died before Test 1 for a reason unrelated to the
hypothesis, and because Leg A was separately blocking the job at the time. Both
of those are fixed, so 636 was set again to see whether Test 1 would finally
execute under it. It did not: same `0x8007203A`, same `0x80072028`, EventId 108
absent again, dead at `minPwdLength` again.

That closes the hypothesis rather than leaving it unproven. **The port cannot be
tested this way at all**, because `LdapPort` governs both the context-acquisition
port and the port in the `DirectoryEntry` path — and 636 breaks acquisition
before any password change is attempted. If the SSL fallback cannot carry a
*context*, it cannot carry a password change either. The port is back to 389, and
the explicit-bind limitation is a known limitation with an **unidentified cause**
rather than one with an untried fix.

#### Both errors are now explained, and neither means what it first appeared to

**`0x8007203A` was ours.** The provider chose channel options and port
independently, so `LdapPort: 636` produced a *sealed, non-SSL* bind aimed at 636.
Port 636 is TLS from the first byte; an LDAP BindRequest is not something it can
answer, and "the server is not operational" is the client reporting that protocol
mismatch. No directory would have behaved differently. This was a client-side
pairing defect and is fixed — see `LdapChannelPorts`, which makes the invalid
combination unrepresentable rather than merely discouraged. The SSL fallback then
fired against a failure the code had manufactured for itself.

**`0x80072028` is Samba behaving as designed, not a fault in the fallback.**
Since CVE-2016-2112 the default is `ldap server require strong auth = yes`,
documented as: simple binds only over TLS-encrypted connections, and unencrypted
connections only with SASL sign or seal. `Negotiate | SecureSocketLayer` is a
*SASL bind over TLS*, which that default excludes — deliberately. Samba does not
implement LDAP channel binding, so there is no cryptographic tie between the NTLM
or Kerberos token and the TLS layer, leaving a relay attack open; it refuses the
combination rather than accept an unsafe session.

**This is Samba-specific.** Real AD *does* implement channel binding — that is
what ADV190023 concerns — so `Negotiate | SecureSocketLayer` is a valid
combination against a real DC. An earlier version of this section called the SSL
fallback "unproven at best" on the strength of that error. That overstated the
evidence: the fallback is **untestable against Samba by design**, which is a
different claim and not a defect in PassCore. The contrast that seemed damning —
a raw `LdapConnection` with SSL succeeding to the same host and port in the same
job — is explained too: that probe uses a *simple* bind over TLS, which the same
Samba default explicitly permits.

What does follow is narrower and still true: **the SSL fallback has no coverage.**
It is reached only when the primary channel fails, which against a correctly
paired 389 never happens, so nothing in CI exercises it either way.

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
