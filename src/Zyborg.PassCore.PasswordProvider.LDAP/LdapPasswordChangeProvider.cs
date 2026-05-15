using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using LdapRemoteCertificateValidationCallback =
    Novell.Directory.Ldap.RemoteCertificateValidationCallback;

namespace Zyborg.PassCore.PasswordProvider.LDAP;

/// <summary>
/// LDAP-based password change provider using Novell.Directory.Ldap.
/// Designed to behave consistently across:
/// - Active Directory
/// - Generic LDAP servers
/// - Mock providers (e.g. MokAPI)
///
/// Guarantees:
/// - User existence is checked before authorization
/// - User must prove knowledge of current password
/// - Infrastructure failures never surface as auth or policy errors
/// </summary>
public sealed class LdapPasswordChangeProvider : PasswordChangeProviderBase, IGroupMembershipTester
{
    private readonly LdapPasswordChangeOptions _options;
    private readonly LdapSearchConstraints _searchConstraints;
    private readonly LdapRemoteCertificateValidationCallback? _certValidator;

    private static readonly string[] RequiredAttributes =
    {
        "distinguishedName",
        "sAMAccountName",
        "memberOf",
    };

    public LdapPasswordChangeProvider(
        ILogger<LdapPasswordChangeProvider> logger,
        IOptions<LdapPasswordChangeOptions> options,
        IOptions<ClientSettings> clientSettings,
        IEnumerable<IPasswordPolicy> policies)
        : base(logger, clientSettings?.Value, policies)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
        ValidateOptions(_options);

        // First find user DN by username (SAM Account Name)
        _searchConstraints = new(
            0,
            0,
            LdapSearchConstraints.DerefNever,
            1000,
            true,
            1,
            null,
            10);

        if (_options.LdapIgnoreTlsErrors || _options.LdapIgnoreTlsValidation)
            _certValidator = ValidateServerCertificate;
    }

    // ---------------------------------------------------------------------
    // Group membership lookup
    // ---------------------------------------------------------------------

    public Task<bool> IsMemberOfGroupAsync(string username, string groupName)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(groupName);

        var user = FindUser(username);

        // `memberOf` returns full DNs (e.g. "cn=Admins,ou=groups,dc=example,dc=com").
        // Compare against the group's RDN value or its full DN, never as a substring,
        // so that "Admins" cannot accidentally match "AdminsExtra".
        var isMember = user.Groups.Any(dn =>
            DnMatchesGroup(dn, groupName));

        return Task.FromResult(isMember);
    }

    private static bool DnMatchesGroup(string dn, string groupName)
    {
        if (string.Equals(dn, groupName, StringComparison.OrdinalIgnoreCase))
            return true;

        // Extract the first RDN value (the bit before the first comma, after the '=').
        var firstComma = dn.IndexOf(',', StringComparison.Ordinal);
        var rdn = firstComma >= 0 ? dn[..firstComma] : dn;

        var equals = rdn.IndexOf('=', StringComparison.Ordinal);
        if (equals < 0)
            return false;

        var cn = rdn[(equals + 1)..].Trim();
        return string.Equals(cn, groupName, StringComparison.OrdinalIgnoreCase);
    }

    // ---------------------------------------------------------------------
    // Password change entry point
    // ---------------------------------------------------------------------

    protected override Task ChangePasswordCore(
        PasswordChangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        try
        {
            // 1. Resolve user DN
            var user = FindUser(context.Username);

            // 2. Verify current credentials (portable across LDAP servers)
            VerifyUserCredentials(user.DistinguishedName, context.CurrentPassword);

            // 3. Perform password change using administrative context
            ChangePassword(user.DistinguishedName, context);
        }
        catch (PasswordChangeException)
        {
            throw;
        }
        catch (LdapException ex)
        {
            throw TranslateLdapException(ex);
        }
        catch (Exception ex)
        {
            throw new DirectoryUnavailableException(
                "Unexpected LDAP infrastructure failure", ex);
        }

        return Task.CompletedTask;
    }

    // ---------------------------------------------------------------------
    // User resolution
    // ---------------------------------------------------------------------

    private LdapUser FindUser(string username)
    {
        var safeUsername = SanitizeUsername(username);
        var filter = _options.LdapSearchFilter.Replace(
            "{Username}", safeUsername, StringComparison.Ordinal);

        using var ldap = BindAsServiceAccount();

        var search = ldap.Search(
            _options.LdapSearchBase,
            LdapConnection.ScopeSub,
            filter,
            RequiredAttributes,
            false,
            _searchConstraints);

        if (!search.HasMore())
        {
            if (_options.HideUserNotFound)
                throw new InvalidCredentialsException("Invalid username or password");

            throw new UserNotFoundException("User not found");
        }

        var entry = search.Next();

        var attributeSet = entry.GetAttributeSet();

        var memberOfKey = attributeSet.Keys
            .FirstOrDefault(k => k.Equals("memberOf", StringComparison.OrdinalIgnoreCase));

        var groups = memberOfKey != null
            ? attributeSet[memberOfKey].StringValueArray ?? Array.Empty<string>()
            : Array.Empty<string>();

        return new LdapUser(entry.Dn, groups);
    }

    // ---------------------------------------------------------------------
    // Credential verification
    // ---------------------------------------------------------------------

    private void VerifyUserCredentials(string userDn, string password)
    {
        try
        {
            using var ldap = Bind(userDn, password);
        }
        catch (LdapBindException ex)
        {
            throw new InvalidCredentialsException("Invalid current password", ex);
        }
    }

    // ---------------------------------------------------------------------
    // Password modification
    // ---------------------------------------------------------------------

    private void ChangePassword(string userDn, PasswordChangeContext context)
    {
        using var ldap = BindAsServiceAccount();

        if (_options.LdapChangePasswordWithDelAdd)
        {
            ChangePasswordDelAdd(
                ldap, userDn,
                context.CurrentPassword,
                context.NewPassword);
        }
        else
        {
            ChangePasswordReplace(
                ldap, userDn,
                context.NewPassword);
        }
    }

    private static void ChangePasswordReplace(
        LdapConnection ldap, string userDn, string newPassword)
    {
        var attr = new LdapAttribute("userPassword", newPassword);
        ldap.Modify(userDn, new[] {
            new LdapModification(LdapModification.Replace, attr)
        });
    }

    private static void ChangePasswordDelAdd(
        LdapConnection ldap,
        string userDn,
        string oldPassword,
        string newPassword)
    {
        var oldBytes = Encoding.Unicode.GetBytes($"\"{oldPassword}\"");
        var newBytes = Encoding.Unicode.GetBytes($"\"{newPassword}\"");

        ldap.Modify(userDn, new[]
        {
            new LdapModification(
                LdapModification.Delete,
                new LdapAttribute("unicodePwd", oldBytes)),
            new LdapModification(
                LdapModification.Add,
                new LdapAttribute("unicodePwd", newBytes))
        });
    }

    // ---------------------------------------------------------------------
    // LDAP connection helpers
    // ---------------------------------------------------------------------

    /// <summary>
    /// Binds as the configured service account. A bind failure here is treated
    /// as an infrastructure error (the operator misconfigured the bind credentials),
    /// never as an end-user authentication error.
    /// </summary>
    private LdapConnection BindAsServiceAccount()
    {
        try
        {
            return Bind(_options.LdapUsername, _options.LdapPassword);
        }
        catch (LdapBindException ex)
        {
            throw new DirectoryUnavailableException(
                "Failed to bind as the configured LDAP service account.", ex);
        }
    }

    /// <summary>
    /// Connects to one of the configured hosts and binds with the supplied
    /// credentials. Connect-time failures fall through to the next host;
    /// bind failures (post-connect) surface as <see cref="LdapBindException"/>
    /// so callers can decide whether to treat them as auth or infra failures.
    /// </summary>
    private LdapConnection Bind(string bindDn, string password)
    {
        LdapException? lastConnectException = null;

        foreach (var host in _options.LdapHostnames)
        {
            var ldap = new LdapConnection();
            if (_certValidator != null)
                ldap.UserDefinedServerCertValidationDelegate += _certValidator;

            try
            {
                ldap.SecureSocketLayer = _options.LdapSecureSocketLayer;
                ldap.Connect(host, _options.LdapPort);

                if (_options.LdapStartTls)
                    ldap.StartTls();
            }
            catch (LdapException ex)
            {
                lastConnectException = ex;
                ldap.Dispose();
                continue; // Try the next host
            }

            try
            {
                ldap.Bind(bindDn, password);
                return ldap;
            }
            catch (LdapException bindEx)
            {
                ldap.Dispose();
                throw new LdapBindException(bindEx);
            }
        }

        throw new DirectoryUnavailableException(
            "Failed to connect to any configured LDAP hostname",
            lastConnectException);
    }

    /// <summary>
    /// Marker exception raised when the LDAP bind step (rather than the
    /// connect step) fails. Lets callers distinguish a wrong password from
    /// an unreachable host while keeping the original <see cref="LdapException"/>
    /// available as <see cref="System.Exception.InnerException"/>.
    /// </summary>
    private sealed class LdapBindException : Exception
    {
        public LdapBindException(LdapException inner)
            : base(inner.Message, inner)
        {
        }
    }

    // ---------------------------------------------------------------------
    // Error translation
    // ---------------------------------------------------------------------

    private static Exception TranslateLdapException(LdapException ex)
    {
        if (string.IsNullOrWhiteSpace(ex.LdapErrorMessage))
            return new DirectoryUnavailableException(
                "Unexpected LDAP error", ex);

        var match = Regex.Match(ex.LdapErrorMessage,
            "([0-9a-fA-F]+):");

        if (!match.Success)
            return new DirectoryUnavailableException(
                ex.LdapErrorMessage, ex);

        var code = int.Parse(
            match.Groups[1].Value,
            NumberStyles.HexNumber);

        return new DirectoryUnavailableException(
            $"LDAP error (Win32 code {code})", ex);
    }

    // ---------------------------------------------------------------------
    // Utilities
    // ---------------------------------------------------------------------

    private static void ValidateOptions(LdapPasswordChangeOptions opts)
    {
        if (opts.LdapHostnames == null || opts.LdapHostnames.Length == 0)
            throw new ArgumentException("LDAP hostnames not configured");

        if (string.IsNullOrWhiteSpace(opts.LdapUsername))
            throw new ArgumentException("LDAP bind DN not configured");

        if (string.IsNullOrWhiteSpace(opts.LdapPassword))
            throw new ArgumentException("LDAP bind password not configured");

        if (string.IsNullOrWhiteSpace(opts.LdapSearchBase))
            throw new ArgumentException("LDAP search base not configured");

        if (!opts.LdapSearchFilter.Contains("{Username}", StringComparison.Ordinal))
            throw new ArgumentException("Search filter must include {Username}");
    }

    private static string SanitizeUsername(string username)
    {
        var clean = username.Split('@')[0];
        if (Regex.IsMatch(clean, @"[""/\\\[\]:;|=,+*?<>]"))
            throw new InvalidCredentialsException(
                "Invalid username format");

        return clean;
    }

    private bool ValidateServerCertificate(
        object sender,
        X509Certificate cert,
        X509Chain chain,
        System.Net.Security.SslPolicyErrors errors)
    {
        if (_options.LdapIgnoreTlsErrors)
            return true;

        return errors == System.Net.Security.SslPolicyErrors.None;
    }

    private sealed record LdapUser(
        string DistinguishedName,
        IReadOnlyCollection<string> Groups);
}
