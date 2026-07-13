namespace Unosquare.PassCore.Common;

/// <summary>
/// Server-side selection of how much a failed password change discloses to the
/// caller. Configured once (the <c>AppSettings:ErrorDisclosureMode</c> key) and
/// enforced inside <see cref="DirectoryErrorTranslator"/>, so both providers
/// always apply the same posture. This value must never be exposed through any
/// client-visible payload — a readable posture flag would tell an attacker
/// which oracle exists.
/// </summary>
public enum ErrorDisclosureMode
{
    /// <summary>
    /// Enumeration-resistant default: unknown-user and unusable-account
    /// (locked, disabled, expired, hours/workstation-restricted) conditions are
    /// indistinguishable from a wrong password, giving an unauthenticated
    /// caller no account-existence or account-state oracle.
    /// </summary>
    Hardened = 0,

    /// <summary>
    /// Help-desk-friendly: unknown users are reported as not found and
    /// unusable accounts as not permitted to change the password ("stop
    /// retrying, contact IT"), at the cost of exposing those oracles to
    /// unauthenticated callers.
    /// </summary>
    Informative = 1,
}
