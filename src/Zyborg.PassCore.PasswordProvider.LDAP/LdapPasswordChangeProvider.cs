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
        "memberOf"
    };

    public LdapPasswordChangeProvider(
        ILogger<LdapPasswordChangeProvider> logger,
        IOptions<LdapPasswordChangeOptions> options,
        IEnumerable<IPasswordPolicy> policies)
        : base(logger, policies)
    {
        _options = options.Value ?? throw new ArgumentNullException(nameof(options));
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
        return Task.FromResult(
                user.Groups.Any(g =>
                    g.Contains(groupName, StringComparison.OrdinalIgnoreCase)));

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
                throw new InvalidCredentialsException();

            throw new UserNotFoundException("User not found");
        }

        var entry = search.Next();

        var groups = entry
            .GetAttribute("memberOf")?
            .StringValueArray
            ?? Array.Empty<string>();

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
        catch (LdapException ex)
        {
            throw new InvalidCredentialsException(
                "Invalid current password", ex);
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

    private LdapConnection BindAsServiceAccount() =>
        Bind(_options.LdapUsername, _options.LdapPassword);

    private LdapConnection Bind(string bindDn, string password)
    {
        var ldap = new LdapConnection();
        if (_certValidator != null)
            ldap.UserDefinedServerCertValidationDelegate += _certValidator;

        foreach (var host in _options.LdapHostnames)
        {
            try
            {
                ldap.SecureSocketLayer = _options.LdapSecureSocketLayer;
                ldap.Connect(host, _options.LdapPort);

                if (_options.LdapStartTls)
                    ldap.StartTls();

                ldap.Bind(bindDn, password);
                return ldap;
            }
            catch (LdapException)
            {
                // try next host
            }
        }

        throw new DirectoryUnavailableException(
            "Failed to connect to any configured LDAP hostname");
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
