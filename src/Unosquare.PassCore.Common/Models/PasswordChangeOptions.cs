using System.Collections.Generic;
using System;

namespace Unosquare.PassCore.Common.Models;

/// <summary>
/// Represents the options for password change providers.
/// </summary>
public class PasswordChangeOptions : IAppSettings
{
    private string? _defaultDomain;
    private string? _ldapPassword;
    private string[]? _ldapHostnames;
    private string? _ldapUsername;

    /// <summary>
    /// Gets or sets a value indicating whether [use automatic context].
    /// </summary>
    public bool UseAutomaticContext { get; set; } = true;

    /// <summary>
    /// Gets or sets the restricted AD groups.
    /// </summary>
    public List<string>? RestrictedADGroups { get; set; }

    /// <summary>
    /// Gets or sets the allowed AD groups.
    /// </summary>
    public List<string>? AllowedADGroups { get; set; }

    /// <summary>
    /// Gets or sets the identifier type for user.
    /// </summary>
    public string? IdTypeForUser { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether [update last password].
    /// </summary>
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

    /// <summary>
    /// Gets or sets a value indicating whether to enable pwned password checks.
    /// </summary>
    public bool EnablePwnedCheck { get; set; }
}
