using System;
using System.Globalization;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Builds ADSI paths for <c>System.DirectoryServices.DirectoryEntry</c>.
/// </summary>
/// <remarks>
/// <para><see cref="System.DirectoryServices"/>' <c>DirectoryEntry</c> takes an ADSI
/// path, not a server address. A bare <c>host:port</c> has no provider scheme and
/// binds nothing: it fails with <c>0x80005000</c>, <c>E_ADS_BAD_PATHNAME</c>. That
/// is what the AD provider was passing on the explicit-bind path, so every request
/// logged a minimum-length lookup failure and advertised the fallback of 6.</para>
/// <para>A scheme alone is still not enough for this particular read.
/// <c>minPwdLength</c> lives on the <b>domain naming context</b> object, not on the
/// server root, so <c>LDAP://host:port</c> would bind somewhere the attribute does
/// not exist and return <see langword="null"/>. That is worse than the error: the
/// caller treats an absent value as "not published by this directory" and stops
/// warning, so the failure becomes invisible.</para>
/// <para>Lives here rather than beside the provider so it can be tested on any
/// platform; the provider itself compiles only under <c>WINDOWS</c>.</para>
/// </remarks>
public static class AdsiPath
{
    /// <summary>The LDAP provider scheme, including its separator.</summary>
    public const string LdapScheme = "LDAP://";

    /// <summary>
    /// Builds the path to a server's rootDSE, the well-known entry point that
    /// publishes <c>defaultNamingContext</c>.
    /// </summary>
    /// <param name="host">The directory host name.</param>
    /// <param name="port">The LDAP port.</param>
    public static string ForRootDse(string host, int port) =>
        string.Create(
            CultureInfo.InvariantCulture,
            $"{LdapScheme}{ValidateHost(host)}:{ValidatePort(port)}/RootDSE");

    /// <summary>
    /// Builds the path to a naming context object on a server — for the domain
    /// naming context, the object that actually carries <c>minPwdLength</c>.
    /// </summary>
    /// <param name="host">The directory host name.</param>
    /// <param name="port">The LDAP port.</param>
    /// <param name="namingContext">
    /// The naming context's distinguished name, normally read from the rootDSE's
    /// <c>defaultNamingContext</c>. Reading it is preferred over deriving a DN from
    /// the configured host name, which assumes the two correspond — they need not.
    /// </param>
    public static string ForNamingContext(string host, int port, string namingContext)
    {
        if (string.IsNullOrWhiteSpace(namingContext))
            throw new ArgumentException("The naming context cannot be empty.", nameof(namingContext));

        return string.Create(
            CultureInfo.InvariantCulture,
            $"{LdapScheme}{ValidateHost(host)}:{ValidatePort(port)}/{namingContext.Trim()}");
    }

    private static string ValidateHost(string host) =>
        string.IsNullOrWhiteSpace(host)
            ? throw new ArgumentException("The directory host cannot be empty.", nameof(host))
            : host.Trim();

    private static int ValidatePort(int port) =>
        port is <= 0 or > 65535
            ? throw new ArgumentOutOfRangeException(nameof(port), port, "The port must be between 1 and 65535.")
            : port;
}
