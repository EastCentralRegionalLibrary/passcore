using System;
using Unosquare.PassCore.Common;

namespace Unosquare.PassCore.PasswordProvider;

/// <summary>
/// Represents the options of this provider.
/// </summary>
/// <seealso cref="Unosquare.PassCore.Common.IAppSettings" />
public class PasswordChangeOptions : IAppSettings
{
    private string? _defaultDomain;
    private string? _ldapPassword;
    private string[]? _ldapHostnames;
    private string? _ldapUsername;

    /// <summary>
    /// Gets or sets a value indicating whether to acquire the principal context
    /// from the host's current domain credentials. When <c>false</c> the
    /// <see cref="IAppSettings.LdapUsername"/> / <see cref="IAppSettings.LdapPassword"/>
    /// values are used to bind explicitly.
    /// </summary>
    public bool UseAutomaticContext { get; set; } = true;

    /// <summary>
    /// Gets or sets the identifier type used to look up the user
    /// (UPN, SAM, DN, GUID, SID or Name).
    /// </summary>
    public string? IdTypeForUser { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether [update last password].
    /// </summary>
    /// <value>
    ///   <c>true</c> if [update last password]; otherwise, <c>false</c>.
    /// </value>
    public bool UpdateLastPassword { get; set; }

    /// <inheritdoc />
    public string DefaultDomain
    {
        get => _defaultDomain ?? string.Empty;
        set => _defaultDomain = value;
    }

    /// <inheritdoc />
    public int LdapPort { get; set; }

    /// <inheritdoc />
    public string[] LdapHostnames
    {
        get => _ldapHostnames ?? Array.Empty<string>();
        set => _ldapHostnames = value;
    }

    /// <inheritdoc />
    public string LdapPassword
    {
        get => _ldapPassword ?? string.Empty;
        set => _ldapPassword = value;
    }

    /// <inheritdoc />
    public string LdapUsername
    {
        get => _ldapUsername ?? string.Empty;
        set => _ldapUsername = value;
    }
}