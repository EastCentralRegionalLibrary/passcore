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

**Status: open, but no longer mysterious.** Against the containerised Samba AD DC,
with `UseAutomaticContext: false` and explicit service-account credentials, reads
work and the password change does not. `SDSUtils.ChangePassword` — the ADSI call
behind `UserPrincipal.ChangePassword` — fails.

**The short version, from server-side audit logging:** the directory records **no
authentication attempt at all** for the change, while the service account's binds
and the end user's credential verification both succeed against that same
directory moments earlier. ADSI gives up *before it contacts the directory*. That
is what `ERROR_CANT_ACCESS_DOMAIN_INFO` describes, and it is consistent with a
runner that is not domain-joined and so has no domain configuration to read. It
is **not** a transport problem, **not** a permissions problem, and **not**
something the directory refused — the directory never sees it.

Whether a **domain-joined** host running `UseAutomaticContext: false` is affected
is untested, and is the one question worth spending a real machine on.

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

### Server-side evidence: what ADSI actually does

Obtained once Samba's logging was genuinely in effect — see the note below on how
long that took to achieve, because the failures along the way were all mine.

Samba's authentication audit, one line per bind, across a full run:

```
33x Auth: [LDAP,NTLMSSP] user [EXAMPLE][Administrator] ... status [NT_STATUS_OK]
 4x Auth: [LDAP,simple bind/TLS] user [EXAMPLE][EXAMPLEAdministrator] ... status [NT_STATUS_OK]
 3x Auth: [Kerberos KDC,ENC-TS Pre-authentication] user [(null)][testuser@example.com] ... status [NT_STATUS_OK]
 3x Auth: [LDAP,NTLMSSP] user [][testuser@example.com] ... status [NT_STATUS_NOT_FOUND]
```

And the failing one in full:

```
Auth: [LDAP,NTLMSSP] user []\[testuser@example.com] with [NTLMv2]
  status [NT_STATUS_NOT_FOUND]
  workstation [runnervmhisb5]
  remote host [ipv4:192.168.96.1:63475]   local host [ipv4:10.88.0.2:389]
  clientDomain ""   clientAccount "testuser@example.com"

ntlm_password_check: LM password and LMv2 failed for user testuser@example.com,
  and NT MD4 password in LM field not permitted
auth_check_password_recv: sam authentication for user [\testuser@example.com]
  FAILED with error NT_STATUS_NOT_FOUND
```

**Correction to a first reading of this data.** The `NT_STATUS_NOT_FOUND` binds
were initially reported as ADSI's password-change connection failing on username
form. **That was wrong**, and the ordered sequence shows why. Every run produces
this pattern, per permitted account:

```
22:48:57.750  Kerberos KDC,ENC-TS Pre-auth   testuser@example.com   NT_STATUS_OK
22:48:58.110  Kerberos KDC,ENC-TS Pre-auth   testuser@example.com   NT_STATUS_WRONG_PASSWORD
22:48:58.119  LDAP,NTLMSSP                   testuser@example.com   NT_STATUS_NOT_FOUND
```

Every single `NOT_FOUND` is preceded ~9ms earlier by a Kerberos
`WRONG_PASSWORD` for the same account. Those pairs are the **`restore` cleanup**
in the smoke test, which posts `NewPassword123!` as the current password — a
password that was never set, because the change failed. Kerberos correctly
rejects it, ADSI then retries over NTLM, and NTLM cannot resolve a bare UPN with
an empty domain. It is an artefact of the test's own teardown, not the defect.

**What the sequence actually establishes is stronger and simpler:**

- The service account's sealed binds succeed — `LDAP,NTLMSSP` as
  `[EXAMPLE][Administrator]`, `NT_STATUS_OK`, four per request.
- The end user's credential verification succeeds — `Kerberos ENC-TS
  Pre-authentication`, `NT_STATUS_OK`, immediately before the change is attempted.
- **The password change itself produces no authentication event on the DC at
  all.** Nothing between the successful verification and the failure. No LDAPS
  bind, no `kpasswd`, no SAMR, no rejected bind of any kind.

So `IADsUser::ChangePassword` is failing **before it authenticates to the
directory** — which is exactly what `0x80070547` `ERROR_CANT_ACCESS_DOMAIN_INFO`
describes: a client-side failure to read domain configuration, not a request the
DC refused. The DC never sees the operation.

That closes the transport question in the opposite direction from the one
originally pursued. ADSI is not choosing badly among LDAPS, Kerberos and SMB and
running out of options; it is not getting as far as choosing. Consistent with
this, the SMB/445 line of enquiry is **not** worth pursuing: there is no
fall-through to reach it.

It also means the remaining explanation is a property of the client environment —
a machine that is not domain-joined, with no computer account and no domain
configuration to read — rather than of PassCore's code or of the directory. That
matches the standing plan to verify against a real domain-joined host, and makes
that verification the decisive test rather than one more CI round.

### Is there a working write path at all?

Two write paths were probed directly from the runner, bypassing PassCore, because
the subject under test is the platform rather than the provider.

```
=== Probe A: IADsUser::SetPassword as the service account ===
  FAILED: COMException: The RPC server is unavailable. (0x800706BA)

=== SMB reachability ===
  10.88.0.2:445 REACHABLE

=== Probe B: NetUserChangePassword with an explicit domain ===
  [example.com]:    SUCCEEDED (NET_API_STATUS 0)   restore returned 0
  [dc.example.com]: failed with NET_API_STATUS 1351
```

**There is a working write path.** `NetUserChangePassword`, given the *domain*
name, changed `probeuser`'s password and changed it back, and Samba's audit log
records the matching Kerberos pre-authentications. So the directory is writable
from this host; what fails is specific to how ADSI resolves its target.

#### `AllowAdministrativeReset` does not work in this configuration

Probe A is precisely what that feature calls. It fails with `0x800706BA`, "the RPC
server is unavailable" — `SetPassword` goes over SAMR/DCE-RPC to the server named
in the `DirectoryEntry` path, and that name resolves to an address where RPC is
not served.

This is a finding in its own right and worth stating plainly: **a shipped feature
is non-functional in the configuration under test.** It is not merely unhelpful
here — `AllowAdministrativeReset` cannot rescue anything on a non-domain-joined
explicit-bind host, because the API it depends on cannot reach the directory.

Note also that it would not have fired even if it worked. `AdministrativeReset.-
ShouldAttempt` requires `ChangeNotPermitted` with the current password verified,
and this failure classifies as infrastructure. Widening that condition is **not**
the fix and should not be done casually: it would make administrative resets fire
on genuine transport failures, which is the same trade already rejected when
reclassifying `ERROR_ACCESS_DENIED`. Recorded as an open decision, not taken.

#### The `1351` correlation, and what it suggests

`NetUserChangePassword` returns **1351** when given `dc.example.com` and **0**
when given `example.com`. 1351 is `ERROR_CANT_ACCESS_DOMAIN_INFO` — *the same code
`IADsUser::ChangePassword` fails with*.

That is a strong hint about the mechanism: the same API, handed a **server** name
where a **domain** name is required, produces exactly the error PassCore sees. The
`DirectoryEntry` that `ChangePassword` operates on carries `dc.example.com`. So
ADSI plausibly passes that server name into a domain-shaped lookup and gets the
same 1351 back.

**This is a hypothesis with matching evidence, not a proof.** Nothing here
inspects what ADSI actually passes internally, and it remains consistent with the
established fact that the DC sees no authentication event for the change — a name
that cannot be resolved to a domain never becomes a connection.

### `SetPassword` works — when the entry is bound over LDAPS

Two variants of the same call, in the **same run against the same server
configuration**, so the only variable is the connection the `DirectoryEntry` is
bound on:

```
Probe A   entry bound LDAP://dc.example.com:389/…  Secure|Signing|Sealing
  FAILED: COMException 0x800706BA "The RPC server is unavailable."

Probe A2  entry bound LDAP://dc.example.com:636/…  Secure|SecureSocketsLayer
  SUCCEEDED — SetPassword changed probeuser's password, and the restore
  changed it back.
```

**The bound connection determines whether the write succeeds.** That contradicts
the assumption this probe was written under — the comment in the workflow said
ADSI opens its own connection for the write regardless, so A2 "should" have
matched A. It did not, and that difference is the finding.

It also explains `0x800706BA` properly. `SetPassword` tries LDAP over a 128-bit
SSL connection, then Kerberos, then `NetUserSetInfo` over RPC. Reaching an RPC
error means the first two had already failed. Give it an entry that is *already*
on an SSL connection and the first method succeeds, so it never reaches RPC.

#### What this means for `AllowAdministrativeReset`

PR 63 recorded that feature as non-functional on this path. It is more precise
than that: **it is non-functional as PassCore currently binds.**
`AcquirePrincipalContext` binds sign-and-seal on `LdapPort` (389), and
`GetDirectoryEntry` builds its path from the same port, so the entry the reset
would act on is a 389-bound one — exactly Probe A, exactly the RPC failure.

So the requirement is not merely "LDAPS reachable and the certificate trusted".
It is that **the `DirectoryEntry` the reset operates on must itself be bound over
LDAPS**. PassCore does not do that today, and no configuration value makes it do
so: setting `LdapPort: 636` breaks context acquisition outright, as recorded
above.

That is a product change rather than a documentation fix, and it is a small and
well-targeted one — the reset path already builds its own entry.

#### What is not yet separated

Both probes ran with Samba's `ldap server require strong auth` relaxed to
`allow_sasl_over_tls`. So while the A-versus-A2 comparison is controlled and the
LDAPS binding is definitively the discriminating variable, **whether A2 would
also succeed against Samba's default is untested**. Prior evidence suggests it
would not: the `LdapPort: 636` experiment showed `Negotiate | SecureSocketLayer`
refused with `0x80072028`, which is that same default denying a SASL bind over
TLS.

This distinction is CI-only. Real AD implements LDAP channel binding — which is
what Samba lacks and why it refuses — so SASL over TLS is accepted there
natively. The production requirement is the same either way: an LDAPS-bound entry
and a trusted certificate.

### Assessment: should PassCore adopt `NetUserChangePassword`?

**Recommendation: adopt behind an explicit opt-in option, gated on the specific
failure — do not adopt unconditionally, and do not adopt silently.**

1. **Which domain form works.** Only the domain (`example.com`). The server form
   (`dc.example.com`) returns 1351. Any adoption must pass the *domain*, which
   PassCore has as `DefaultDomain` or can derive from the UPN — notably it must
   **not** reuse `LdapHostnames`, which is deliberately set to the DC's FQDN and is
   exactly the form that fails.

2. **Operational cost — the real objection.** It requires SMB/445 reachability
   from the application host to a domain controller. That is a materially bigger
   firewall ask than LDAP: PassCore is frequently deployed in a DMZ precisely so
   that only 389/636 need to be open, and 445 outbound to a DC is blocked by
   policy in many of those environments. It worked here only because the static
   route makes the container's own 445 reachable. This cost is why it must be
   opt-in rather than an automatic fallback.

3. **Gating, precisely.** A new option (default **false**), and even when enabled
   it is attempted *only* after `ChangePassword` has failed with `0x80070547`
   specifically — not on any failure, and never before ADSI has been tried. A
   domain-joined host where `ChangePassword` works therefore never reaches it, and
   an operator who has not opened 445 never has a request quietly routed there.

4. **Error surface — smaller than feared.** `NET_API_STATUS` is not an HRESULT, so
   `DirectoryErrorTranslator.TryGetWin32Code` will not recover it. But the values
   are Win32/lmerr codes in the same numeric space the existing `Win32ErrorCode`
   catalog already describes — `86` invalid password, `2221` user not found,
   `2245` password too short, `5` access denied, `1351`, `53`/`1722` unreachable.
   The work is to wrap the returned `int` so the catalog can classify it, not to
   invent a second taxonomy. Doing it any other way would reproduce the misrouted
   errors this project spent months eliminating.

5. **Security properties — unchanged, with one thing to verify.** It authenticates
   with the user's **own old password**, so it cannot change a password without
   it, and it cannot perform an administrative reset. It uses no service-account
   privilege, so it grants nothing the current flow does not already permit, and
   the existing verify-before-write ordering is untouched. The one thing not to
   assume: that the exchange is encrypted. Modern SMB negotiates encryption and
   RPC sealing, but that should be confirmed on the target platform rather than
   inferred, since a password crosses it.

**What would change the recommendation.** If the domain-joined verification shows
`ChangePassword` failing there too, this stops being a workaround for one
environment and becomes the only working path for every explicit-bind deployment
— at which point the SMB requirement is worth paying and the option's default
deserves revisiting. If `ChangePassword` works when domain-joined, this stays a
narrow escape hatch and may not be worth carrying at all.

### A note on how long the instrumentation took

Five rounds, and the honest summary is that four of them were wasted on my own
mistakes rather than on the problem:

1. `log level = 3` — wrong debug class; LDAP binds are logged by `auth_audit`.
2. Added the `auth_audit` classes — right classes, but looked for the output in
   `/var/log/samba`, where the AD DC does not write.
3. Enumerated instead of guessing, which found it: supervisord runs
   `/usr/sbin/samba -i`, so the log is
   `/var/log/supervisor/samba-stderr---supervisor-<random>.log`.
4. Added `logging = file`, which redirected output away from that working capture.
5. Added a `testparm` check — **and it immediately showed the settings had never
   applied at all.** `podman restart` re-runs the image entrypoint, which
   regenerates `smb.conf` and discarded every edit before Samba read it. The
   `smb.conf` dump looked correct each time because it runs *before* the restart.

The fix was `supervisorctl restart samba`, which re-execs the daemon without the
entrypoint. **The lesson is round 5's:** every earlier round verified the *file*
and inferred the *process state* from it. Asking the running system what it
believes — `testparm` — broke the loop in one attempt and should have been first.

It also means two things recorded earlier were wrong and are retracted:
`allow_sasl_over_tls` was never in force, so it is **untested**, not refuted; and
the empty logs were never evidence about ADSI.

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
