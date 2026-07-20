# Upgrade note: unified error routing (error-disclosure + admin-reset)

This release reworked how both real providers (Active Directory and LDAP)
report password-change failures, so identical directory conditions produce
identical responses. It adds two server-side settings and changes several
default behaviors. Nothing about the wire contract changed — see
[`error-routing-matrix.md`](./error-routing-matrix.md) for the full mapping.

**Bottom line:** most deployments need no config change. Two situations do:
LDAP sites that relied on `HideUserNotFound: false`, and AD service-account
sites that relied on the old silent administrative reset. Both are covered
below.

## New settings (both under `AppSettings`, server-side only)

Neither is ever sent to the browser.

| Setting | Default | Effect |
|---------|---------|--------|
| `ErrorDisclosureMode` | `Hardened` | `Hardened`: unknown users and locked/disabled/restricted accounts are indistinguishable from a wrong password (no account oracle). `Informative`: unknown users get "user not found" and unusable accounts get "contact IT" guidance. |
| `AllowAdministrativeReset` | `false` | When on, an account flagged "user cannot change password" completes its change as an administrative reset by the service account (after the current password is verified). This is the **only** condition it rescues. |

## Action may be required

### LDAP: you set `HideUserNotFound: false`

`HideUserNotFound` is deprecated and **ignored**; disclosure is now governed by
`ErrorDisclosureMode`. While the old key remains in your config a startup
warning is logged.

- You had `HideUserNotFound: true` (or unset) → no change; hardened default
  matches. Remove the stale key to silence the warning.
- You had `HideUserNotFound: false` (you *wanted* user-not-found disclosed) →
  set `"ErrorDisclosureMode": "Informative"` to restore that behavior, then
  remove `HideUserNotFound`.

### AD: you run service-account mode (`UseAutomaticContext: false`)

Previously **every** failed `ChangePassword` was silently retried as an
administrative `SetPassword` — silently bypassing password history and
minimum-age policy for all users. That silent fallback is **gone**.

- Domain policy rejections (history, minimum age, complexity) now surface to
  the user as a policy error (`ComplexPassword`) and are **never** rescued,
  even with `AllowAdministrativeReset: true`. This is intentional — the option
  no longer bypasses intentional policy.
- If you relied on the fallback specifically to let **cannot-change-flagged**
  accounts through, set `"AllowAdministrativeReset": true`. Every such reset is
  now logged at Warning with a correlation ID, and only fires after the current
  password is verified.

### Either provider: inert option combinations (startup warning only)

`AllowAdministrativeReset` is ignored, with a logged warning, when:

- AD `UseAutomaticContext: true` (no service account to reset with), or
- LDAP `LdapChangePasswordWithDelAdd: false` (that mechanism is already an
  administrative replace).

Remove the option in those cases, or switch the mode/mechanism if you want it.

## Automatic changes (no action needed)

- **Uniform credential responses.** All "invalid credentials" responses now
  share one wire message. On AD, an unknown username now reports invalid
  credentials instead of user-not-found by default (the hardened posture).
- **No raw text on the wire.** `Generic` errors shown in the UI now read
  *"An unexpected error occurred (ref: …)"* with a reference that correlates to
  the server log, instead of a raw .NET/LDAP exception string. Pwned-password
  (HIBP) outages show a clean retry message instead of client internals.
- **LDAP cannot-change correction.** On AD-backed LDAP, an account flagged
  "user cannot change password" now reports `ChangeNotPermitted` (after
  verification) instead of being misreported as an LDAP/infrastructure problem.
- **Flagged-account probing closed.** A flagged account probed with a wrong
  password now returns invalid credentials in both modes, instead of disclosing
  the flag before authentication. If a help-desk flow depended on that
  pre-auth signal, it must now verify the current password first.
- **Reworded default alerts.** The shipped `Alerts.ErrorComplexPassword` and
  `Alerts.ErrorPasswordChangeNotAllowed` strings were reworded to read
  correctly for the broader set of conditions now routed to them. If you
  override these in your own config, your text is untouched.

## What did not change

- **`ApiErrorCode`** — no values added, renumbered, or removed. The wire
  numbers are unchanged, so existing clients keep working.
- **`ClientApp`** — no application code changed (only two E2E test-expectation
  strings were updated to match the reworded alerts).
- **Client settings payload** — the two new settings are server-side only and
  do not appear in any client-visible response.
- **Non-AD LDAP servers** — cannot-change detection reads AD security
  descriptors; where that is unavailable it is skipped (logged at Debug) and
  behavior is exactly as before.

## Verification status

The routing matrix and cross-provider convergence are covered by unit tests
(`RoutingMatrixAuditTests`, `ProviderParityTests`). Two items require a live
directory and were **not** exercised in CI — validate them in a staging domain
before rollout if they matter to you:

1. End-to-end administrative reset of a real cannot-change-flagged account
   (option on → change completes with a Warning log; option off → user sees
   `ChangeNotPermitted`), on **both** providers.
2. The LDAP security-descriptor scan against a real AD `nTSecurityDescriptor`
   (unit fixtures are hand-built from the MS-DTYP binary format).

The Windows-only AD provider is not compiled by the cross-platform CI; its
edits were compile-verified separately and it delegates to the same shared,
fully-tested translator as the LDAP provider.
