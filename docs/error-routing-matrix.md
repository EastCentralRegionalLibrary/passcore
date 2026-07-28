# Error routing matrix

The single reference for how PassCore turns a directory failure into something
the user sees. It is the source of truth for anyone adding or changing a
password-change provider.

Every row here is machine-verified by
`RoutingMatrixAuditTests` (in `Zyborg.PassCore.PasswordProvider.LDAP.Tests`).
If you change a routing decision, change that test and this document together —
they are meant to disagree only while a change is in progress.

## The one rule for provider authors

**A provider never decides an `ApiErrorCode` itself.** It extracts a Win32/AD
error code from whatever transport it speaks (an LDAP extended-error string, a
COM `HResult`, a `LogonUser` last-error) and hands it to the shared
`DirectoryErrorTranslator`. The translator owns the mapping below. This is why
the two real providers produce identical results for identical conditions, and
it is the only way to keep that true as providers are added.

Structural conditions that have no error code (an empty search result, a null
principal, a detected "cannot change password" flag, a group membership restriction/rejection) use the dedicated
factories `DirectoryErrorTranslator.CreateUserNotFoundError` /
`CreateChangeNotPermittedError` / `CreateGroupRejectionError`, which apply the same table.

## Two message layers (read this before touching messages)

A response carries an `ApiErrorItem { ErrorCode: int, Message: string }`. There
are two different strings in play and it is easy to confuse them:

1. **The wire `Message`** — a fixed, curated constant set by the translator
   (the "wire message" column below). It never contains raw exception or
   server text. For every non-`Generic` code **the browser ignores it.**
2. **The displayed alert** — the frontend (`ChangePassword.tsx`) maps the
   **integer** `ErrorCode` to an admin-configured string from
   `ClientSettings.Alerts` (the "UI alert" column below) and shows that. The
   wire `Message` is shown to the user **only** for `Generic` (code `0`), which
   is why `Generic` must never carry raw text (it now carries
   `"An unexpected error occurred (ref: …)"`).

Consequence: the frontend map is keyed by the raw enum integer. That is the
reason for the append-only rule further down.

## Win32 / AD code → failure class

The catalog lives in `Unosquare.PassCore.Common/Win32ErrorCode.cs`. Uncataloged
codes classify as `Infrastructure` (safe default). AD emits these codes in two
extended-error shapes (leading code for modify-time `WILL_NOT_PERFORM`; `data`
sub-code for bind-time errors) and as `FACILITY_WIN32` HRESULTs; all three
reduce to the same code.

| Code | Name | Failure class |
|------|------|---------------|
| `0x05` | ERROR_ACCESS_DENIED | Infrastructure |
| `0x56` | ERROR_INVALID_PASSWORD | Credentials |
| `0x523` | ERROR_INVALID_ACCOUNT_NAME | Existence |
| `0x524` | ERROR_USER_EXISTS | Infrastructure |
| `0x525` | ERROR_NO_SUCH_USER | Existence |
| `0x52B` | ERROR_WRONG_PASSWORD | Credentials |
| `0x52C` | ERROR_ILL_FORMED_PASSWORD | NewPasswordPolicy |
| `0x52D` | ERROR_PASSWORD_RESTRICTION | NewPasswordPolicy |
| `0x52E` | ERROR_LOGON_FAILURE | Credentials |
| `0x52F` | ERROR_ACCOUNT_RESTRICTION | AccountState |
| `0x530` | ERROR_INVALID_LOGON_HOURS | AccountState |
| `0x531` | ERROR_INVALID_WORKSTATION | AccountState |
| `0x532` | ERROR_PASSWORD_EXPIRED | PasswordExpiredOrMustChange |
| `0x533` | ERROR_ACCOUNT_DISABLED | AccountState |
| `0x701` | ERROR_ACCOUNT_EXPIRED | AccountState |
| `0x773` | ERROR_PASSWORD_MUST_CHANGE | PasswordExpiredOrMustChange |
| `0x774` | ERROR_DOMAIN_CONTROLLER_NOT_FOUND | Infrastructure |
| `0x775` | ERROR_ACCOUNT_LOCKED_OUT | AccountState |
| `0x8C3` | NERR_PasswordCantChange | ChangeNotPermitted |
| `0x8C4` | NERR_PasswordHistConflict | NewPasswordPolicy |
| `0x8C5` | NERR_PasswordTooShort | NewPasswordPolicy |
| `0x8C6` | NERR_PasswordTooRecent | NewPasswordPolicy |

## The routing matrix: failure class × disclosure mode

`ErrorDisclosureMode` (server-side only, default `Hardened`) is the only knob
that changes the outcome for a given class. `PasswordExpiredOrMustChange` never
reaches this table during a change — it is consumed at credential-verification
time as *proof of the current password* and the change proceeds (both
providers, via `DirectoryErrorTranslator.IsPasswordExpiredOrMustChange`); it is
shown only for completeness.

| Failure class | Mode | ApiErrorCode (int) | Wire message | UI alert (`Alerts.*`) |
|---------------|------|--------------------|--------------|-----------------------|
| Credentials | both | InvalidCredentials (4) | `InvalidCredentialsMessage` | `ErrorInvalidCredentials` |
| Existence | Hardened | InvalidCredentials (4) | `InvalidCredentialsMessage` | `ErrorInvalidCredentials` |
| Existence | Informative | UserNotFound (3) | `UserNotFoundMessage` | `ErrorInvalidUser` |
| AccountState | Hardened | InvalidCredentials (4) | `InvalidCredentialsMessage` | `ErrorInvalidCredentials` |
| AccountState | Informative | ChangeNotPermitted (6) | `AccountStateMessage` | `ErrorPasswordChangeNotAllowed` |
| Group Rejection | Hardened | InvalidCredentials (4) | `InvalidCredentialsMessage` | `ErrorInvalidCredentials` |
| Group Rejection | Informative | ChangeNotPermitted (6) | `AccountStateMessage` | `ErrorPasswordChangeNotAllowed` |
| NewPasswordPolicy | both | ComplexPassword (9) | `NewPasswordPolicyMessage` | `ErrorComplexPassword` |
| ChangeNotPermitted | both | ChangeNotPermitted (6) | `ChangeNotPermittedMessage` | `ErrorPasswordChangeNotAllowed` |
| Infrastructure | both | LdapProblem (8) | `DirectoryFailureMessage` | `ErrorConnectionLdap` |
| PasswordExpiredOrMustChange | both | *(allowed through — change proceeds)* | — | — |

The wire-message constants live on `DirectoryErrorTranslator`. In **Hardened**
mode the Credentials / Existence / AccountState / Group Rejection rows are byte-identical on the
wire (same code, same message), so an unauthenticated caller gets no
account-existence or account-state oracle. **Informative** mode trades that
oracle for actionable help-desk guidance.

### Reachability caveat: `AccountState | Informative`

That row describes what the translator produces when it is *asked* to translate
an account-state code. It is **not** what a locked-out, disabled, or
logon-hours-restricted user sees when they try to change their password —
in the ordinary case they get `InvalidCredentials` in *both* modes.

The reason is that account state is discovered at **credential-verification**
time, and neither provider routes that step through the translator; both
hardcode `InvalidCredentialsException` for anything that is not
expired/must-change:

- **AD** — `ValidateUserCredentials` returns `false` for every code except
  `0x532` / `0x773`, and the caller throws `InvalidCredentialsException`. (The
  code itself is not lost: it is attached as the inner exception and reaches
  the log — see "Diagnostics" below.)
- **LDAP** — `VerifyUserCredentials` catches `LdapBindException`, checks
  expired/must-change, and otherwise throws `InvalidCredentialsException` with
  the bind failure as the inner exception.

So the `AccountState | Informative` row is reachable only from **modify-time**
account-state errors — a lockout that occurs mid-request, or a logon-hours
boundary crossed between verification and modify — which is a narrow window,
not the everyday case.

Two facts worth having straight, because they are the inputs to a pending
decision about whether verification-time failures should route through
`Translate(code, mode, DirectoryActor.User)` (that decision has **not** been
made; nothing here advocates either way):

- **Existence and account state are treated differently within Informative
  mode.** Both providers call `CreateUserNotFoundError(mode)` when the lookup
  finds nobody — before any credential check — so in Informative mode a
  nonexistent user *is* disclosed pre-verification, while a locked or disabled
  one is not disclosed at all. As far as the audit could establish this is an
  inconsistency rather than a deliberate distinction.
- **In Hardened mode the question is moot.** The translator collapses
  account-state to `InvalidCredentials` regardless, so only Informative-mode
  deployments would see any difference from such a change.

### Diagnostics: what the wire hides, the log keeps

Hardened mode's collapse is deliberate, which makes the server log the
compensating control for the conditions it hides. Both providers attach the
underlying failure to the thrown `InvalidCredentialsException` as an **inner
exception** — AD via `CredentialFailureDetail.ForWin32Code` (a
`Win32Exception` carrying the code, plus the catalog name and curated
description when the code is cataloged), LDAP via the original
`LdapBindException`. The base class logs it at Warning with the correlation ID
(EventId 4), so an operator can distinguish a lockout from a mistyped password.

`ApiErrorMapper.Map` reads only `Exception.Message` and never walks
`InnerException`, so none of this detail can reach `ApiErrorItem.Message` or
any other wire field, in either mode.

## The actor dimension: same code, different actor, different class

The Win32 code alone does not say **whose** credentials failed. A bind that
fails with `0x52E` (ERROR_LOGON_FAILURE) is the **end user** proving their
current password when it comes from the credential-verification step, but the
application's own **service account** when it comes from connecting to or
resolving against the directory. Reporting the latter as "invalid username or
password" tells an end user their password is wrong when the real fault is a
misconfigured service account.

So every translation carries a `DirectoryActor`, and the class is computed by
`ClassifyForActor(code, actor)`:

| Actor | Effect on classification |
|-------|--------------------------|
| `User` (default) | Classified normally per the catalog. Every pre-existing caller gets this. |
| `ServiceAccount` | The end-user-account signals — `Credentials`, `Existence`, `AccountState`, `PasswordExpiredOrMustChange` — collapse to `Infrastructure`. A service-account or connectivity failure can therefore **never** produce `InvalidCredentials` / `UserNotFound`; it is always `LdapProblem` + `DirectoryFailureMessage`, in both disclosure modes. `NewPasswordPolicy` / `ChangeNotPermitted` are left untouched (a connect/resolve step cannot raise them). |

This is the single enforcement point for "a service-account failure is never an
end-user credential failure." Providers pick the actor at the call site:

- **LDAP** — `BindAsServiceAccount` translates with `ServiceAccount`;
  `VerifyUserCredentials` and the modify path stay `User`. The distinction is by
  call site, the reference behavior since the unified-routing work.
- **AD** — `RunAsServiceAccount` wraps the service-account operations
  (`AcquirePrincipalContext`, `FindByIdentity`, group reads) and translates
  their failures with `ServiceAccount`; the modify path stays `User`, and the
  end user's own wrong password is the explicit `InvalidCredentialsException`
  from `ValidateUserCredentials`, unaffected.

A `ServiceAccount` failure is also logged at Warning by `ServiceAccountFailure`
(correlation ID when available, operation, host, underlying code) — the operator
gets the diagnosis while the wire response stays curated. `0x532`
(ERROR_PASSWORD_EXPIRED) is worth noting: as the **user** it is "proceed, the
password is correct but expired"; as the **service account** it must never
proceed — the actor coercion makes it `Infrastructure`.

### Undetermined group membership

`IsMemberOfGroupAsync` answers `true`/`false` only when the answer is known. A
lookup that **could not complete** is a third outcome, and it is not reported as
"not a member": the provider throws, the failure routes as
`DirectoryActor.ServiceAccount` → `Infrastructure`, and the caller gets
`LdapProblem (8)` / `DirectoryFailureMessage` in both modes — the `Infrastructure`
row above, not the `Group Rejection` row.

This is why the distinction is load-bearing rather than pedantic.
`GroupMembershipPolicy` reads the result as a `bool`, so conflating the two makes
`RestrictedAdGroups` **fail open**: during a partial directory failure, a
service-account permissions problem, or a cross-domain timeout, a member of a
restricted group would be handed a password change. (`AllowedAdGroups` fails the
other way — every user refused, with no operator signal.) Failing closed is the
point of a deny list, so an unknown answer blocks the request.

A match is definitive the moment it is found, so a later lookup failing never
turns a confirmed membership into code 8 — a restricted-group member still gets
the `Group Rejection` row. Only a *negative* answer requires that every lookup
which could still have matched actually ran:

- **LDAP** — direct `memberOf`, the `primaryGroupToken` search, and the
  `LDAP_MATCHING_RULE_IN_CHAIN` search. `memberOf` succeeding does not cover
  nesting or the primary group, so it cannot rescue either search's failure.
- **AD** — `GetAuthorizationGroups` (transitive plus primary security groups) and
  `GetGroups` (direct, including distribution groups). They cover different
  ground, so neither rescues the other's failure.

An empty result set is a completed lookup, not a failure: ordinary
non-membership stays an ordinary `false` and the request proceeds. Each failed
lookup is logged at Warning through `ServiceAccountFailure` with the operation
that failed, so the operator can see why requests started being refused.

## Terminal catch

Both providers end `ChangePasswordCore` with the same last-resort
`catch (Exception ex)`: **construct `DirectoryUnavailableException(
DirectoryFailureMessage, ex)` directly — do not re-scan the chain for a Win32
code.** Every failure that carries a meaningful directory code is already
handled at its stage (typed `LdapException` / `TryGetWin32Code` extraction for
the transport, service-account operations via `BindAsServiceAccount` /
`RunAsServiceAccount`, the modify itself in the LDAP `ChangePasswordDelAdd`
catch and the AD `UpdatePassword` catch). An exception reaching the terminal
catch is therefore an unexpected, non-directory-typed fault with no reliable
code, so speculative extraction there is inappropriate — it could only
mislabel a non-directory fault. Classifying it as infrastructure is correct and
identical on both providers. (Earlier the AD provider re-scanned via
`TranslateException` here while the LDAP provider did not; standardized on the
LDAP behavior.) The raw detail stays in the inner exception for logs, never on
the wire.

## The administrative-reset fallback dimension

`AllowAdministrativeReset` (server-side, default off) adds a second dimension,
but it changes the outcome for **exactly one** class:

| Failure class | Reset off (default) | Reset on (+ current password verified) |
|---------------|---------------------|-----------------------------------------|
| ChangeNotPermitted | surfaces as the table row above | **rescued**: password set administratively, logged at Warning |
| every other class | surfaces as the table row above | **unchanged** — surfaces identically |

Eligibility is decided in one place, `AdministrativeReset.ShouldAttempt`, which
returns true only for `ChangeNotPermitted` with the option enabled **and** the
user's current credentials verified in the same request. It never rescues
password-policy rejections (intentional policy is honored), account-state
conditions, or infrastructure failures, and never runs before verification.

## `ApiErrorCode` is append-only

Because the frontend maps the **integer** value of `ApiErrorCode` to alert
strings (see "Two message layers"), the wire numbers are a contract with the
client:

- **Never** renumber, reorder, or remove a member.
- New members may only be **appended** (next unused integer), and adding one
  requires a matching entry in the frontend `errorMessages` map and a new
  `Alerts.*` string — otherwise the UI falls back to *"An unknown error
  occurred."*
- Prefer reusing an existing code with a curated message over adding a member.
  The whole series added **zero** members: `0x52C`/`0x52D` deliberately collapse
  into `ComplexPassword`, and account-state in informative mode reuses
  `ChangeNotPermitted`.

## Where the decisions live (choke points)

| Concern | Single location |
|---------|-----------------|
| Code → failure class | `Win32ErrorCode.Codes` catalog |
| Code + actor → failure class | `DirectoryErrorTranslator.ClassifyForActor` |
| Class × mode → domain exception | `DirectoryErrorTranslator.Translate` |
| Exception → `ApiErrorCode` | `ApiErrorMapper.Map` |
| Expired/must-change "allow through" | `DirectoryErrorTranslator.IsPasswordExpiredOrMustChange` |
| Service-account failure diagnostics | `ServiceAccountFailure.Log` |
| Reset-fallback eligibility | `AdministrativeReset.ShouldAttempt` |
| Disclosure mode / reset options | `IAppSettings` (bound from `AppSettings`, server-side only) |

A provider supplies only transport-specific extraction, **chooses the actor for
each operation**, and calls into these.

## Known follow-up: Debug provider fidelity

The Debug provider (`DebugPasswordChangeProvider`, the E2E reference) forces a
final `ApiErrorCode` directly and **does not** route through
`DirectoryErrorTranslator`. It therefore cannot simulate the two dimensions the
series introduced:

- the same underlying condition rendering differently under
  `Hardened` vs `Informative` (it emits a fixed code regardless of mode), and
- the administrative-reset fallback (cannot-change → reset vs. `ChangeNotPermitted`).

This is acceptable for its current role (it still forces every terminal
`ApiErrorCode`, including `UserNotFound`, `ChangeNotPermitted`, and
`ComplexPassword`), but a future change could let it opt into translator-backed
behavior so E2E can exercise mode/fallback end-to-end. Filed as a follow-up
rather than expanded here, per the Phase 4 scope.
