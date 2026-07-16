namespace Unosquare.PassCore.Common;

/// <summary>
/// Interface for any Application provider.
/// </summary>
public interface IAppSettings
{
    /// <summary>
    /// Gets or sets the error-disclosure posture applied when a password
    /// change fails. Server-side only — never expose this value through a
    /// client-visible payload.
    /// </summary>
    /// <remarks>
    /// Optional, defaults to <see cref="ErrorDisclosureMode.Hardened"/>
    /// (unknown users and unusable accounts are indistinguishable from a
    /// wrong password). Set to <see cref="ErrorDisclosureMode.Informative"/>
    /// to give legitimate users actionable guidance (user-not-found and
    /// contact-IT responses) at the cost of exposing an account-existence
    /// and account-state oracle to unauthenticated callers.
    /// </remarks>
    /// <value>
    /// The error disclosure mode.
    /// </value>
    ErrorDisclosureMode ErrorDisclosureMode { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether a failed user-context password
    /// change may fall back to an administrative reset performed with the
    /// configured service account.
    /// </summary>
    /// <remarks>
    /// Optional, defaults to <see langword="false"/>. When enabled, the reset
    /// rescues exactly one condition: the account is flagged so the user
    /// cannot change their own password (the AD "User cannot change password"
    /// setting). It fires only after the user's current password was verified
    /// in the same request. It never rescues password-policy rejections
    /// (length, complexity, history, minimum age — intentional policy is
    /// honored), never account-state conditions (locked, disabled,
    /// hours/workstation restrictions), and never infrastructure failures;
    /// all of those surface as errors. Ignored by the AD provider in
    /// automatic-context mode (no service account to reset with), and by the
    /// LDAP provider when <c>LdapChangePasswordWithDelAdd</c> is
    /// <see langword="false"/> (the Replace mechanism is already an
    /// administrative operation). Every reset is logged at Warning with the
    /// request correlation ID. Note administrative resets are not subject to
    /// password history or minimum-age policy.
    /// </remarks>
    /// <value>
    ///   <c>true</c> to allow the administrative reset fallback; otherwise, <c>false</c>.
    /// </value>
    bool AllowAdministrativeReset { get; set; }

    /// <summary>
    /// Gets or sets the default domain.
    /// </summary>
    /// <value>
    /// The default domain.
    /// </value>
    string DefaultDomain { get; set; }

    /// <summary>
    /// Gets or sets the LDAP port.
    /// </summary>
    /// <remarks>
    /// Optional, defaults to 636 -- the default port for LDAPS (i.e. LDAP over TLS).
    /// A common alternative is to use the default LDAP port, 389, however this port
    /// typically is not-secured and requires the "StartTLS" flag enabled.
    /// </remarks>
    /// <value>
    /// The LDAP port.
    /// </value>
    int LdapPort { get; set; }

    /// <summary>
    /// Gets or sets the LDAP hostnames.
    /// </summary>
    /// <remarks>
    ///  Required, one or more hostnames or IP addresses which expose an LDAP/LDAPS
    /// service endpoint that will be connected to.  If more than one host is
    /// specified, then each will be tried in turn until a successful, secure
    /// connection is established.
    /// </remarks>
    /// <value>
    /// The LDAP hostnames.
    /// </value>
    string[] LdapHostnames { get; set; }

    /// <summary>
    /// Gets or sets the LDAP password.
    /// </summary>
    /// <value>
    /// The LDAP password.
    /// </value>
    string LdapPassword { get; set; }

    /// <summary>
    /// Gets or sets the LDAP username.
    /// </summary>
    /// <value>
    /// The LDAP username.
    /// </value>
    string LdapUsername { get; set; }
}