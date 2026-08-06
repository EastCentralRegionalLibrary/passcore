using System;
using System.Linq;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Validates the directory-connection settings shared by both providers:
/// <see cref="IAppSettings.LdapHostnames"/>, <see cref="IAppSettings.LdapUsername"/>,
/// and <see cref="IAppSettings.LdapPassword"/>.
/// </summary>
/// <remarks>
/// Whether these three are required differs by provider: the AD provider only needs
/// them for an explicit bind (<c>UseAutomaticContext == false</c>), while the LDAP
/// provider always binds explicitly and needs them unconditionally. Rather than each
/// provider re-implementing the same three checks, both call this with their own
/// answer to "is a service account required here".
/// </remarks>
public static class AppSettingsValidation
{
    /// <summary>
    /// Validates <see cref="IAppSettings.LdapHostnames"/>,
    /// <see cref="IAppSettings.LdapUsername"/>, and
    /// <see cref="IAppSettings.LdapPassword"/> on <paramref name="settings"/>.
    /// </summary>
    /// <param name="settings">The settings to validate.</param>
    /// <param name="required">
    /// Whether a service account is required for this provider's configuration. When
    /// <see langword="false"/>, no check is performed at all.
    /// </param>
    /// <exception cref="ArgumentException">
    /// <paramref name="required"/> is <see langword="true"/> and the hostnames are
    /// missing, empty, or contain no non-blank entry; or the username or password is
    /// missing, empty, or whitespace.
    /// </exception>
    public static void ValidateServiceAccount(IAppSettings settings, bool required)
    {
        ArgumentNullException.ThrowIfNull(settings);

        if (!required)
            return;

        if (settings.LdapHostnames == null
            || settings.LdapHostnames.Length == 0
            || settings.LdapHostnames.All(string.IsNullOrWhiteSpace))
            throw new ArgumentException("Hostnames are not configured.");

        if (string.IsNullOrWhiteSpace(settings.LdapUsername))
            throw new ArgumentException("Service account username is not configured.");

        if (string.IsNullOrWhiteSpace(settings.LdapPassword))
            throw new ArgumentException("Service account password is not configured.");
    }
}
