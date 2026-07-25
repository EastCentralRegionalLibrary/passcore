# Upgrade note: unified error routing (error-disclosure + admin-reset)

This release reworked how both real providers (Active Directory and LDAP)
report password-change failures, so identical directory conditions produce
identical responses. It adds two server-side settings and changes several
default behaviors. Nothing about the wire contract changed — see
[`error-routing-matrix.md`](./error-routing-matrix.md) for the full mapping.

**Bottom line:** most deployments need no config change. Two situations do:
LDAP sites that relied on `HideUserNotFound: false`, and AD service-account
sites that relied on the old silent administrative reset. Both are covered
below. One AD setting — `UpdateLastPassword` — was **removed**; leaving it in
your config is harmless, and the removal is also covered below.

## New settings (both under `AppSettings`, server-side only)

Neither is ever sent to the browser.

| Setting | Default | Effect |
|---------|---------|--------|
| `ErrorDisclosureMode` | `Hardened` | `Hardened`: unknown users and locked/disabled/restricted accounts are indistinguishable from a wrong password (no account oracle). `Informative`: unknown users get "user not found" and unusable accounts get "contact IT" guidance. |
| `AllowAdministrativeReset` | `false` | When on, an account flagged "user cannot change password" completes its change as an administrative reset by the service account (after the current password is verified). This is the **only** condition it rescues. |

## Removed setting: `UpdateLastPassword` (AD provider)

**No action needed.** It is documented here because it was found during this
series' audit and because it interacts with the administrative-reset change
below.

The AD provider had an `UpdateLastPassword` option that, when enabled, wrote
`pwdLastSet = -1` to the user's directory entry **before** the caller's current
password had been verified. The option, the write, and the `SetLastPassword`
method that performed it are gone. `PasswordChangeOptions` no longer has the
property, and the key is no longer in the shipped `appsettings.json`.

Why it went away:

- **It ran before authentication.** Everything preceding credential
  verification runs for a caller who has supplied nothing but a username. Per
  Microsoft's ADSI documentation, `pwdLastSet = 0` means "user must change
  password at next logon" and `-1` *removes* that requirement (no other value
  can be written by anything but the system). The old code's comment claimed
  it forced a change at next logon; it did the opposite. So a caller who knew
  a valid username — and no password — could clear the must-change flag, and a
  help-desk-issued temporary password would silently stop being temporary.
- **AD maintains `pwdLastSet` itself.** The schema defines it as the time the
  password was last changed, its update privilege is "set by the system", and
  it is stamped on every successful password change or administrative reset.
  There was nothing for PassCore to maintain.
- **It defeated the change it was trying to enable.** The `pwdLastSet == 0`
  state is what exempts an account from the domain's *minimum password age*.
  Writing `-1` destroyed that exemption and started the minimum-age clock, so
  the change attempted moments later was rejected by AD (`0x52D`). The default
  domain policy sets a minimum password age of 1 day, so this was the default
  configuration, not an edge case. It used to be masked by the old always-on
  administrative `SetPassword` fallback (resets bypass minimum age); now that
  the fallback is opt-in and off by default, the failure had become visible —
  reported as `ComplexPassword`, which is misleading for a minimum-age
  rejection.

What changes for you:

- **You never set it (the default, `false`)** → nothing changes at all.
- **You set `"UpdateLastPassword": true`** → accounts flagged "user must change
  password at next logon" should now work *better*. Their flag is left alone,
  they keep their minimum-age exemption, credential verification recognises the
  must-change state as proof of the current password and proceeds, and the
  change succeeds. Nothing that worked before stops working.
- **A stale key is harmless.** Configuration binding ignores unknown keys, so a
  deployment whose `appsettings.json` still contains `"UpdateLastPassword"`
  starts normally. Delete the line at your convenience. (Unlike
  `HideUserNotFound` below, there is no startup warning for it: detecting the
  stale key would require keeping a property for it, which is exactly the shim
  the removal set out to avoid.)

Forcing a must-change *after* a successful administrative reset — writing
`pwdLastSet = 0`, the opposite operation — is a separate feature that has not
been built and is not implied by this removal.

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
fully-tested translator as the LDAP provider. Because it cannot be loaded or
exercised from the cross-platform suite at all, the two properties that have no
shared-code equivalent — no directory write before credential verification, and
no `ApiErrorCode` decided inside the provider — are held by a source audit,
`AdProviderDirectoryWriteAuditTests`.
