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
/// - User must prove knowledge of current password (on Active Directory,
///   expired / must-change-at-next-logon passwords still count as proof)
/// - User-supplied input cannot alter the structure of the LDAP search filter
/// - Infrastructure failures never surface as auth or policy errors
/// </summary>
public sealed class LdapPasswordChangeProvider : PasswordChangeProviderBase, IGroupMembershipTester
{
    private readonly LdapPasswordChangeOptions _options;
    private readonly LdapSearchConstraints _searchConstraints;
    private readonly LdapRemoteCertificateValidationCallback? _certValidator;

    // AD operation errors lead with the Win32 code, e.g.
    // "0000052D: SvcErr: DSID-031A12D2, problem 5003 (WILL_NOT_PERFORM), data 0".
    private static readonly Regex LeadingHexCodeRegex =
        new("^\\s*([0-9a-fA-F]{1,8}):", RegexOptions.CultureInvariant);

    // AD bind errors lead with a generic SEC_E code and carry the Win32 code
    // in the "data" field, e.g.
    // "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 52e, v2580".
    private static readonly Regex DataSubCodeRegex =
        new("\\bdata\\s+([0-9a-fA-F]+)", RegexOptions.CultureInvariant);

    // Characters that are never valid in a sAMAccountName, per AD naming rules.
    private static readonly Regex InvalidAccountNameCharsRegex =
        new(@"[""/\\\[\]:;|=,+*?<>]", RegexOptions.CultureInvariant);

    private static readonly Action<ILogger, Exception?> LogNoTransportSecurity =
        LoggerMessage.Define(
            LogLevel.Warning,
            new EventId(100, nameof(LogNoTransportSecurity)),
            "Neither LdapSecureSocketLayer nor LdapStartTls is enabled; user credentials " +
            "and new passwords will be sent to the LDAP server unencrypted. Enable one of " +
            "them unless the connection is protected by other means (e.g. a local test server).");

    private static readonly Action<ILogger, ErrorDisclosureMode, Exception?> LogHideUserNotFoundDeprecated =
        LoggerMessage.Define<ErrorDisclosureMode>(
            LogLevel.Warning,
            new EventId(101, nameof(LogHideUserNotFoundDeprecated)),
            "The HideUserNotFound setting is deprecated and has no effect. User-not-found " +
            "disclosure is controlled by ErrorDisclosureMode (currently {ErrorDisclosureMode}): " +
            "'Hardened' hides unknown users like HideUserNotFound=true did; 'Informative' " +
            "discloses them like HideUserNotFound=false did. Remove HideUserNotFound from the " +
            "configuration and set ErrorDisclosureMode explicitly if the default is not wanted.");

    private static readonly Action<ILogger, Exception?> LogAdminResetIneffective =
        LoggerMessage.Define(
            LogLevel.Warning,
            new EventId(102, nameof(LogAdminResetIneffective)),
            "AllowAdministrativeReset is enabled but LdapChangePasswordWithDelAdd is false, so it " +
            "has no effect: the Replace change mechanism is already an administrative operation " +
            "performed by the service account. Remove AllowAdministrativeReset or switch to the " +
            "delete/add mechanism if a fallback from a user-style change is what you want.");

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

        if (!_options.LdapSecureSocketLayer && !_options.LdapStartTls)
            LogNoTransportSecurity(Logger, null);

        if (_options.HideUserNotFound.HasValue)
            LogHideUserNotFoundDeprecated(Logger, _options.ErrorDisclosureMode, null);

        if (_options.AllowAdministrativeReset && !_options.LdapChangePasswordWithDelAdd)
            LogAdminResetIneffective(Logger, null);

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

        try
        {
            var user = FindUser(username);

            // `memberOf` returns full DNs (e.g. "cn=Admins,ou=groups,dc=example,dc=com").
            // Compare against the group's RDN value or its full DN, never as a substring,
            // so that "Admins" cannot accidentally match "AdminsExtra".
            var isMember = user.Groups.Any(dn =>
                DnMatchesGroup(dn, groupName));

            return Task.FromResult(isMember);
        }
        catch (PasswordChangeException)
        {
            throw;
        }
        catch (LdapException ex)
        {
            throw TranslateLdapException(ex, _options.ErrorDisclosureMode);
        }
        catch (Exception ex)
        {
            // Deliberately broad: group lookups run inside policy evaluation, and
            // any exception that escapes here surfaces to the wire as Generic plus
            // raw exception text. Wrapping keeps the detail in logs (inner
            // exception) and a curated message on the wire.
            throw new DirectoryUnavailableException(
                DirectoryErrorTranslator.DirectoryFailureMessage, ex);
        }
    }

    internal static bool DnMatchesGroup(string dn, string groupName)
    {
        if (string.Equals(dn, groupName, StringComparison.OrdinalIgnoreCase))
            return true;

        // Extract the first RDN value (the bit before the first unescaped comma,
        // after the '='). RFC 4514 escapes literal commas in RDN values as "\,",
        // which is the form AD uses in memberOf values.
        var firstComma = IndexOfUnescapedComma(dn);
        var rdn = firstComma >= 0 ? dn[..firstComma] : dn;

        var equals = rdn.IndexOf('=', StringComparison.Ordinal);
        if (equals < 0)
            return false;

        var cn = UnescapeRdnValue(rdn[(equals + 1)..].Trim());
        return string.Equals(cn, groupName, StringComparison.OrdinalIgnoreCase);
    }

    private static int IndexOfUnescapedComma(string dn)
    {
        for (var i = 0; i < dn.Length; i++)
        {
            if (dn[i] == '\\')
            {
                i++; // Skip the escaped character
                continue;
            }

            if (dn[i] == ',')
                return i;
        }

        return -1;
    }

    private static string UnescapeRdnValue(string value)
    {
        if (!value.Contains('\\', StringComparison.Ordinal))
            return value;

        var sb = new StringBuilder(value.Length);
        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '\\' && i + 1 < value.Length)
                i++;

            sb.Append(value[i]);
        }

        return sb.ToString();
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

            // 3. Perform password change using administrative context. The
            //    verified flag is derived from control flow: VerifyUserCredentials
            //    throws on failure, so this line is reachable only after the user
            //    proved knowledge of the current password in this request.
            ChangePassword(user.DistinguishedName, context, currentPasswordVerified: true);
        }
        catch (PasswordChangeException)
        {
            throw;
        }
        catch (LdapException ex)
        {
            throw TranslateLdapException(ex, _options.ErrorDisclosureMode);
        }
        catch (Exception ex)
        {
            throw new DirectoryUnavailableException(
                DirectoryErrorTranslator.DirectoryFailureMessage, ex);
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
            // Posture-aware existence handling shared with the AD provider
            // (replaces the deprecated LDAP-only HideUserNotFound switch).
            throw DirectoryErrorTranslator.CreateUserNotFoundError(_options.ErrorDisclosureMode);
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

    /// <summary>
    /// Verifies the user's current credentials by binding as the user.
    /// On Active Directory, a bind rejected only because the password is
    /// expired or must be changed at next logon (resultCode 49 with extended
    /// error data 532/773) still proves the user knows the current password,
    /// so those cases are allowed through — matching the Windows AD provider's
    /// <c>ErrorPasswordMustChange</c>/<c>ErrorPasswordExpired</c> handling.
    /// Generic LDAP servers do not emit these AD-specific data codes, so their
    /// bind failures continue to surface as invalid credentials.
    /// </summary>
    private void VerifyUserCredentials(string userDn, string password)
    {
        try
        {
            using var ldap = Bind(userDn, password);
        }
        catch (LdapBindException ex)
        {
            if (ex.InnerException is LdapException ldapEx && IsPasswordExpiredOrMustChange(ldapEx))
                return;

            throw new InvalidCredentialsException(DirectoryErrorTranslator.InvalidCredentialsMessage, ex);
        }
    }

    /// <summary>
    /// Detects the Active Directory bind failures that mean "the password is
    /// correct but needs changing": resultCode 49 (invalidCredentials) whose
    /// extended error message carries data sub-code 532 (ERROR_PASSWORD_EXPIRED)
    /// or 773 (ERROR_PASSWORD_MUST_CHANGE). Sub-code parsing is LDAP-transport
    /// knowledge and stays here; the decision of which codes count as
    /// expired/must-change is shared via
    /// <see cref="DirectoryErrorTranslator.IsPasswordExpiredOrMustChange(int)"/>.
    /// </summary>
    internal static bool IsPasswordExpiredOrMustChange(LdapException ex)
    {
        if (ex.ResultCode != LdapException.InvalidCredentials)
            return false;

        var message = ex.LdapErrorMessage;
        if (string.IsNullOrEmpty(message))
            return false;

        var data = DataSubCodeRegex.Match(message);
        return data.Success
            && int.TryParse(data.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code)
            && DirectoryErrorTranslator.IsPasswordExpiredOrMustChange(code);
    }

    // ---------------------------------------------------------------------
    // Password modification
    // ---------------------------------------------------------------------

    /// <summary>
    /// Performs the password change. With the delete/add mechanism (AD-style
    /// user change, server-enforced old password and full policy), a failure
    /// may fall back to an administrative <c>unicodePwd</c> replace when
    /// <see cref="LdapPasswordChangeOptions.AllowAdministrativeReset"/> permits
    /// it — see <see cref="TranslateAndDecideRescue"/> for the exact gate. The
    /// Replace mechanism is already administrative, so no fallback applies there.
    /// </summary>
    private void ChangePassword(string userDn, PasswordChangeContext context, bool currentPasswordVerified)
    {
        using var ldap = BindAsServiceAccount();

        if (!_options.LdapChangePasswordWithDelAdd)
        {
            ChangePasswordReplace(
                ldap, userDn,
                context.NewPassword);
            return;
        }

        try
        {
            ChangePasswordDelAdd(
                ldap, userDn,
                context.CurrentPassword,
                context.NewPassword);
        }
        catch (LdapException ex)
        {
            var translated = TranslateAndDecideRescue(ex, _options, currentPasswordVerified, out var attemptReset);
            if (!attemptReset)
                throw translated;

            AdminResetUnicodePwd(ldap, userDn, context.NewPassword);
            AdministrativeReset.LogPerformed(Logger, context.CorrelationId, context.Username, translated);
        }
    }

    /// <summary>
    /// Translates a failed delete/add modification and decides whether the
    /// administrative-reset fallback may fire: option enabled, current password
    /// verified in this request, delete/add mechanism in use, and the failure
    /// is one a reset can cure (new-password policy or cannot-change) — the
    /// shared <see cref="AdministrativeReset.ShouldAttempt"/> gate.
    /// </summary>
    internal static Exception TranslateAndDecideRescue(
        LdapException ex,
        LdapPasswordChangeOptions options,
        bool currentPasswordVerified,
        out bool attemptReset)
    {
        var translated = TranslateLdapException(ex, options.ErrorDisclosureMode);

        attemptReset = options.LdapChangePasswordWithDelAdd
            && AdministrativeReset.ShouldAttempt(
                options.AllowAdministrativeReset,
                currentPasswordVerified,
                translated);

        return translated;
    }

    /// <summary>
    /// Administrative reset of an Active Directory password: a single Replace
    /// of <c>unicodePwd</c> performed by the service account. Bypasses password
    /// history and minimum-age policy; only reachable through the
    /// <see cref="AdministrativeReset"/> gate.
    /// </summary>
    private static void AdminResetUnicodePwd(
        LdapConnection ldap, string userDn, string newPassword)
    {
        var newBytes = Encoding.Unicode.GetBytes($"\"{newPassword}\"");
        ldap.Modify(userDn, new[]
        {
            new LdapModification(
                LdapModification.Replace,
                new LdapAttribute("unicodePwd", newBytes)),
        });
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

    /// <summary>
    /// Maps an <see cref="LdapException"/> raised during search or modify to a
    /// domain exception. This method owns only the LDAP-transport parsing of
    /// Active Directory extended error messages, which come in two shapes:
    /// operation errors lead with the Win32 code
    /// ("0000052D: SvcErr: ..., problem 5003 (WILL_NOT_PERFORM), data 0"), while
    /// bind-style errors lead with a generic SEC_E code and carry the Win32 code
    /// in the "data" field ("80090308: LdapErr: ..., data 52e, v2580"). Routing
    /// of the extracted code is delegated to
    /// <see cref="DirectoryErrorTranslator.Translate(int, ErrorDisclosureMode, Exception?)"/> —
    /// see that class for the per-mode routing table.
    /// Messages with no recognizable Win32 code become a
    /// <see cref="DirectoryUnavailableException"/> whose wire message is a fixed
    /// curated string; the server's diagnostic text survives only in the inner
    /// exception, which reaches logs but never the wire.
    /// </summary>
    internal static Exception TranslateLdapException(LdapException ex, ErrorDisclosureMode disclosureMode)
    {
        var known = string.IsNullOrWhiteSpace(ex.LdapErrorMessage)
            ? null
            : ExtractWin32ErrorCode(ex.LdapErrorMessage);

        return known is null
            ? new DirectoryUnavailableException(DirectoryErrorTranslator.DirectoryFailureMessage, ex)
            : DirectoryErrorTranslator.Translate(known.Code, disclosureMode, ex);
    }

    /// <summary>
    /// Extracts the Win32 error code from an AD extended error message,
    /// preferring the leading hex code when it is a known password-change
    /// code and falling back to the "data" sub-code otherwise. Returns
    /// <see langword="null"/> when neither resolves to a known code, so the
    /// raw server message can be surfaced instead of a mislabeled number.
    /// </summary>
    internal static Win32ErrorCode? ExtractWin32ErrorCode(string message)
    {
        var leading = LeadingHexCodeRegex.Match(message);
        if (leading.Success
            && int.TryParse(leading.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var code)
            && Win32ErrorCode.ByCode(code) is { } fromLeading)
        {
            return fromLeading;
        }

        var data = DataSubCodeRegex.Match(message);
        if (data.Success
            && int.TryParse(data.Groups[1].Value, NumberStyles.HexNumber, CultureInfo.InvariantCulture, out var subCode)
            && Win32ErrorCode.ByCode(subCode) is { } fromData)
        {
            return fromData;
        }

        return null;
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

        if (opts.LdapSecureSocketLayer && opts.LdapStartTls)
            throw new ArgumentException(
                "LdapSecureSocketLayer and LdapStartTls are mutually exclusive: " +
                "StartTLS is issued over a plaintext connection, while SecureSocketLayer " +
                "expects TLS from the first byte. Enable at most one of them.");
    }

    /// <summary>
    /// Produces a value safe to substitute into <see cref="LdapPasswordChangeOptions.LdapSearchFilter"/>:
    /// takes the local part of the username, rejects characters that are never
    /// valid in a sAMAccountName (including control characters and the empty
    /// string), then escapes the remaining RFC 4515 filter metacharacters so the
    /// substituted value cannot alter the structure of the search filter.
    /// </summary>
    internal static string SanitizeUsername(string username)
    {
        var clean = username.Split('@')[0];

        if (clean.Length == 0
            || clean.Any(char.IsControl)
            || InvalidAccountNameCharsRegex.IsMatch(clean))
        {
            throw new InvalidCredentialsException(
                "Invalid username format");
        }

        return EscapeLdapSearchFilterValue(clean);
    }

    /// <summary>
    /// Escapes the characters RFC 4515 §3 requires escaping inside a filter
    /// value: '*', '(', ')', '\' and NUL. Applied after character validation
    /// as defense in depth, so the substituted value is inert in the filter
    /// even if the validation rules are relaxed in the future.
    /// </summary>
    internal static string EscapeLdapSearchFilterValue(string value)
    {
        var sb = new StringBuilder(value.Length);
        foreach (var c in value)
        {
            switch (c)
            {
                case '\\': sb.Append("\\5c"); break;
                case '*': sb.Append("\\2a"); break;
                case '(': sb.Append("\\28"); break;
                case ')': sb.Append("\\29"); break;
                case '\0': sb.Append("\\00"); break;
                default: sb.Append(c); break;
            }
        }

        return sb.ToString();
    }

    /// <summary>
    /// Server certificate validation honoring the TLS options:
    /// <see cref="LdapPasswordChangeOptions.LdapIgnoreTlsErrors"/> accepts any
    /// certificate, while <see cref="LdapPasswordChangeOptions.LdapIgnoreTlsValidation"/>
    /// accepts chain-trust failures only (e.g. self-signed or untrusted CA) and
    /// still rejects name mismatches and other errors.
    /// </summary>
    internal bool ValidateServerCertificate(
        object sender,
        X509Certificate cert,
        X509Chain chain,
        System.Net.Security.SslPolicyErrors errors)
    {
        if (_options.LdapIgnoreTlsErrors)
            return true;

        if (_options.LdapIgnoreTlsValidation)
        {
            return (errors & ~System.Net.Security.SslPolicyErrors.RemoteCertificateChainErrors)
                == System.Net.Security.SslPolicyErrors.None;
        }

        return errors == System.Net.Security.SslPolicyErrors.None;
    }

    private sealed record LdapUser(
        string DistinguishedName,
        IReadOnlyCollection<string> Groups);
}
