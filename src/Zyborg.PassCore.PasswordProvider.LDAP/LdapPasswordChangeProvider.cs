using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;
using System;
using System.Buffers.Binary;
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
public class LdapPasswordChangeProvider : PasswordChangeProviderBase, IGroupMembershipTester
{
    /// <inheritdoc />
    public override ErrorDisclosureMode ErrorDisclosureMode => _options.ErrorDisclosureMode;

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
        "primaryGroupID",
    };

    internal Func<LdapConnection> LdapConnectionFactory { get; set; } = () => new LdapConnection();

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

            // 1. Direct membership check
            // `memberOf` returns full DNs (e.g. "cn=Admins,ou=groups,dc=example,dc=com").
            // Compare against the group's RDN value or its full DN, never as a substring,
            // so that "Admins" cannot accidentally match "AdminsExtra".
            var isMember = user.Groups.Any(dn =>
                DnMatchesGroup(dn, groupName));

            if (isMember)
                return Task.FromResult(true);

            // 2. Primary Group Resolution (both well-known fallback and dynamic search)
            if (!string.IsNullOrEmpty(user.PrimaryGroupId))
            {
                // Robust check for well-known RIDs:
                if (user.PrimaryGroupId == "513" && groupName.Equals("Domain Users", StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(true);
                if (user.PrimaryGroupId == "512" && groupName.Equals("Domain Admins", StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(true);
                if (user.PrimaryGroupId == "519" && groupName.Equals("Enterprise Admins", StringComparison.OrdinalIgnoreCase))
                    return Task.FromResult(true);

                try
                {
                    using var ldap = BindAsServiceAccount();
                    var primaryFilter = $"(primaryGroupToken={user.PrimaryGroupId})";
                    var primarySearch = SearchLdap(
                        ldap,
                        _options.LdapSearchBase,
                        LdapConnection.ScopeSub,
                        primaryFilter,
                        new[] { "distinguishedName" },
                        false,
                        _searchConstraints);

                    if (primarySearch.HasMore())
                    {
                        var primaryDn = primarySearch.Next().Dn;
                        if (DnMatchesGroup(primaryDn, groupName))
                            return Task.FromResult(true);
                    }
                }
                catch (Exception ex) when (ex is LdapException || ex is DirectoryUnavailableException)
                {
                    Logger.LogDebug(ex, "Failed to resolve primary group DN via primaryGroupToken search. Falling back to default evaluation.");
                }
            }

            // 3. Transitive/Nested Group Resolution via LDAP_MATCHING_RULE_IN_CHAIN OID (Active Directory specific)
            try
            {
                using var ldap = BindAsServiceAccount();
                var chainFilter = $"(member:1.2.840.113556.1.4.1941:={user.DistinguishedName})";
                var chainSearch = SearchLdap(
                    ldap,
                    _options.LdapSearchBase,
                    LdapConnection.ScopeSub,
                    chainFilter,
                    new[] { "distinguishedName" },
                    false,
                    _searchConstraints);

                while (chainSearch.HasMore())
                {
                    var entry = chainSearch.Next();
                    if (DnMatchesGroup(entry.Dn, groupName))
                        return Task.FromResult(true);
                }
            }
            catch (Exception ex) when (ex is LdapException || ex is DirectoryUnavailableException)
            {
                Logger.LogDebug(ex, "Failed to resolve transitive groups using LDAP_MATCHING_RULE_IN_CHAIN. Falling back to default evaluation.");
            }

            return Task.FromResult(false);
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
            // 1. Resolve user DN (service-account bind + search)
            var user = FindUser(context.Username, context.CorrelationId);

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
            // Operation errors (search/modify) carry their Win32 code in the
            // extended message; TranslateLdapException extracts and routes it.
            throw TranslateLdapException(ex, _options.ErrorDisclosureMode);
        }
        catch (Exception ex)
        {
            // Terminal backstop, consistent with the AD provider (see the
            // routing-matrix doc, "Terminal catch"). Every failure carrying a
            // meaningful directory code is already handled at its stage — the
            // typed LdapException catch above, and service-account bind failures
            // at BindAsServiceAccount. An exception reaching HERE is an
            // unexpected, non-LDAP fault with no reliable Win32 code, so it is
            // classified as infrastructure directly rather than by speculatively
            // scanning the chain. Raw text stays in the inner exception.
            throw new DirectoryUnavailableException(
                DirectoryErrorTranslator.DirectoryFailureMessage, ex);
        }

        return Task.CompletedTask;
    }

    // ---------------------------------------------------------------------
    // User resolution
    // ---------------------------------------------------------------------

    private LdapUser FindUser(string username, string? correlationId = null)
    {
        var safeUsername = SanitizeUsername(username);
        var filter = _options.LdapSearchFilter.Replace(
            "{Username}", safeUsername, StringComparison.Ordinal);

        using var ldap = BindAsServiceAccount(correlationId);

        var search = SearchLdap(
            ldap,
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

        var primaryGroupIdKey = attributeSet.Keys
            .FirstOrDefault(k => k.Equals("primaryGroupID", StringComparison.OrdinalIgnoreCase));

        var primaryGroupId = primaryGroupIdKey != null
            ? attributeSet[primaryGroupIdKey].StringValue
            : null;

        return new LdapUser(entry.Dn, groups, primaryGroupId);
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
    /// user change, server-enforced old password and full policy), an account
    /// flagged so it cannot change its own password is detected post-verification
    /// via its security descriptor and either rescued with an administrative
    /// <c>unicodePwd</c> replace (when
    /// <see cref="LdapPasswordChangeOptions.AllowAdministrativeReset"/> and the
    /// shared gate permit it) or reported with the curated ChangeNotPermitted
    /// error — fixing the previous misreport of flagged accounts as
    /// infrastructure failures. Modify-time failures route through
    /// <see cref="TranslateAndDecideRescue"/>: only the
    /// <see cref="DirectoryFailureClass.ChangeNotPermitted"/> class is ever
    /// rescuable. The Replace mechanism is already administrative, so neither
    /// detection nor fallback applies there.
    /// </summary>
    private void ChangePassword(string userDn, PasswordChangeContext context, bool currentPasswordVerified)
    {
        using var ldap = BindAsServiceAccount(context.CorrelationId);

        if (!_options.LdapChangePasswordWithDelAdd)
        {
            ChangePasswordReplace(
                ldap, userDn,
                context.NewPassword);
            return;
        }

        // Post-verification pre-flight: a del/add by the service account would be
        // denied for a cannot-change-flagged account and surface as access-denied
        // (infrastructure). Detect the flag from the DACL instead and route it
        // through the same decision seam as modify-time failures. Detection runs
        // only after credential verification, so the flag is never a pre-auth oracle.
        if (DetectCannotChangePassword(ldap, userDn))
        {
            var blocked = DirectoryErrorTranslator.CreateChangeNotPermittedError();
            if (!ShouldRescue(_options, currentPasswordVerified, DirectoryFailureClass.ChangeNotPermitted))
                throw blocked;

            AdminResetUnicodePwd(ldap, userDn, context.NewPassword);
            AdministrativeReset.LogPerformed(Logger, context.CorrelationId, context.Username, blocked);
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
    /// The single rescue-eligibility seam for this provider: delete/add
    /// mechanism in use, plus the shared
    /// <see cref="AdministrativeReset.ShouldAttempt"/> gate (option enabled,
    /// current password verified in this request, and the failure class is
    /// exactly <see cref="DirectoryFailureClass.ChangeNotPermitted"/>). Both
    /// the post-verification pre-flight (detected flag) and the modify-failure
    /// catch route through this method, so eligibility cannot drift between
    /// the two call sites.
    /// </summary>
    internal static bool ShouldRescue(
        LdapPasswordChangeOptions options,
        bool currentPasswordVerified,
        DirectoryFailureClass failureClass) =>
        options.LdapChangePasswordWithDelAdd
        && AdministrativeReset.ShouldAttempt(
            options.AllowAdministrativeReset,
            currentPasswordVerified,
            failureClass);

    /// <summary>
    /// Translates a failed delete/add modification and decides — via
    /// <see cref="ShouldRescue"/> — whether the administrative-reset fallback
    /// may fire. Only a failure classified as
    /// <see cref="DirectoryFailureClass.ChangeNotPermitted"/> is rescuable;
    /// password-policy rejections, account-state conditions (in either
    /// disclosure mode) and infrastructure failures always surface.
    /// </summary>
    internal static Exception TranslateAndDecideRescue(
        LdapException ex,
        LdapPasswordChangeOptions options,
        bool currentPasswordVerified,
        out bool attemptReset)
    {
        var translated = TranslateLdapException(ex, options.ErrorDisclosureMode, out var failureClass);

        attemptReset = ShouldRescue(options, currentPasswordVerified, failureClass);

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

    // ---------------------------------------------------------------------
    // Cannot-change-password detection (AD security descriptor)
    // ---------------------------------------------------------------------

    // LDAP_SERVER_SD_FLAGS_OID with a BER value selecting only the DACL
    // (SEQUENCE { INTEGER 4 } = DACL_SECURITY_INFORMATION), so AD returns
    // nTSecurityDescriptor without requiring SACL rights.
    private const string SdFlagsControlOid = "1.2.840.113556.1.4.801";
    private static readonly byte[] SdFlagsDaclOnly = { 0x30, 0x03, 0x02, 0x01, 0x04 };
    private static readonly string[] SecurityDescriptorAttributes = { "nTSecurityDescriptor" };

    // The User-Change-Password control-access right (MS documented GUID). The
    // "user cannot change password" setting is stored as deny ACEs for this
    // right, granted to Everyone and/or SELF. The distinct
    // User-Force-Change-Password (reset) right, 00299570-246d-11d0-a768-00aa006e0529,
    // must NOT match — resets remain permitted for flagged accounts.
    private static readonly Guid UserChangePasswordRightGuid =
        new("ab721a53-1e2f-11d0-9819-00aa0040529b");

    private static readonly Action<ILogger, string, Exception?> LogSdDetectionSkipped =
        LoggerMessage.Define<string>(
            LogLevel.Debug,
            new EventId(104, nameof(LogSdDetectionSkipped)),
            "Could not read or parse the security descriptor for {UserDn}; skipping " +
            "cannot-change-password detection. This is expected on non-AD servers or when the " +
            "service account cannot read the DACL. The change proceeds normally and any denial " +
            "will surface from the modify operation itself.");

    /// <summary>
    /// Detects the AD "user cannot change password" flag by reading the
    /// target's DACL (SD-flags control, non-critical) and scanning for deny
    /// ACEs on the User-Change-Password right. Any failure to read or parse —
    /// non-AD server, control unsupported, insufficient rights, malformed
    /// bytes — logs at Debug and reports not-flagged, so behavior degrades to
    /// exactly what it was before detection existed.
    /// </summary>
    private bool DetectCannotChangePassword(LdapConnection ldap, string userDn)
    {
        try
        {
            var constraints = new LdapSearchConstraints();
            constraints.SetControls(new LdapControl(SdFlagsControlOid, false, SdFlagsDaclOnly));

            var results = SearchLdap(
                ldap,
                userDn,
                LdapConnection.ScopeBase,
                "(objectClass=*)",
                SecurityDescriptorAttributes,
                false,
                constraints);

            if (!results.HasMore())
            {
                LogSdDetectionSkipped(Logger, userDn, null);
                return false;
            }

            var attributeSet = results.Next().GetAttributeSet();
            var sdKey = attributeSet.Keys
                .FirstOrDefault(k => k.Equals("nTSecurityDescriptor", StringComparison.OrdinalIgnoreCase));
            var sdBytes = sdKey != null ? attributeSet[sdKey].ByteValue : null;

            var denied = SecurityDescriptorDeniesChangePassword(sdBytes);
            if (denied is null)
            {
                LogSdDetectionSkipped(Logger, userDn, null);
                return false;
            }

            return denied.Value;
        }
        catch (Exception ex)
        {
            // Deliberately broad: detection is best-effort and must never turn
            // an unreadable descriptor into a failed password change.
            LogSdDetectionSkipped(Logger, userDn, ex);
            return false;
        }
    }

    /// <summary>
    /// Scans a self-relative Windows security descriptor (MS-DTYP 2.4.6) for a
    /// deny object-ACE (ACCESS_DENIED_OBJECT_ACE_TYPE, MS-DTYP 2.4.4.11) on the
    /// User-Change-Password control-access right granted to Everyone (S-1-1-0)
    /// or SELF (S-1-5-10) — the on-directory representation of the "user cannot
    /// change password" setting. Implemented by hand because the BCL's
    /// <c>RawSecurityDescriptor</c> throws <c>PlatformNotSupportedException</c>
    /// off Windows, and this provider runs cross-platform. Returns
    /// <see langword="true"/> when the flag is set, <see langword="false"/>
    /// when the DACL parsed cleanly without such an ACE, and
    /// <see langword="null"/> when the descriptor is absent or malformed
    /// (callers treat that as "detection unavailable").
    /// </summary>
    internal static bool? SecurityDescriptorDeniesChangePassword(byte[]? securityDescriptor)
    {
        const byte accessDeniedObjectAceType = 0x06;
        const ushort seDaclPresent = 0x0004;

        if (securityDescriptor is null || securityDescriptor.Length < 20)
            return null;

        ReadOnlySpan<byte> data = securityDescriptor;

        if (data[0] != 1) // SECURITY_DESCRIPTOR revision
            return null;

        var control = BinaryPrimitives.ReadUInt16LittleEndian(data.Slice(2, 2));
        if ((control & seDaclPresent) == 0)
            return null;

        var daclOffset = BinaryPrimitives.ReadInt32LittleEndian(data.Slice(16, 4));
        if (daclOffset <= 0 || daclOffset > data.Length - 8)
            return null; // no DACL bytes (a "present" but NULL DACL) or truncated

        var acl = data[daclOffset..];
        var aclSize = BinaryPrimitives.ReadUInt16LittleEndian(acl.Slice(2, 2));
        var aceCount = BinaryPrimitives.ReadUInt16LittleEndian(acl.Slice(4, 2));
        if (aclSize < 8 || aclSize > acl.Length)
            return null;

        var offset = 8;
        for (var i = 0; i < aceCount; i++)
        {
            if (offset + 4 > aclSize)
                return null; // truncated ACE header

            var aceType = acl[offset];
            var aceSize = BinaryPrimitives.ReadUInt16LittleEndian(acl.Slice(offset + 2, 2));
            if (aceSize < 4 || offset + aceSize > aclSize)
                return null; // malformed ACE size

            if (aceType == accessDeniedObjectAceType
                && AceDeniesChangePassword(acl.Slice(offset + 4, aceSize - 4)))
            {
                return true;
            }

            offset += aceSize;
        }

        return false;
    }

    private static bool AceDeniesChangePassword(ReadOnlySpan<byte> aceBody)
    {
        const int adsRightDsControlAccess = 0x100;
        const int aceObjectTypePresent = 0x1;
        const int aceInheritedObjectTypePresent = 0x2;

        // Body layout: Mask(4) Flags(4) [ObjectType GUID 16] [InheritedObjectType GUID 16] SID(...)
        if (aceBody.Length < 4 + 4 + 16)
            return false;

        var mask = BinaryPrimitives.ReadInt32LittleEndian(aceBody.Slice(0, 4));
        if ((mask & adsRightDsControlAccess) == 0)
            return false;

        var flags = BinaryPrimitives.ReadInt32LittleEndian(aceBody.Slice(4, 4));
        if ((flags & aceObjectTypePresent) == 0)
            return false; // no specific right named; not the cannot-change representation

        var objectType = new Guid(aceBody.Slice(8, 16));
        if (objectType != UserChangePasswordRightGuid)
            return false;

        var sidOffset = 8 + 16 + ((flags & aceInheritedObjectTypePresent) != 0 ? 16 : 0);
        return aceBody.Length >= sidOffset + 12 && SidIsEveryoneOrSelf(aceBody[sidOffset..]);
    }

    private static bool SidIsEveryoneOrSelf(ReadOnlySpan<byte> sid)
    {
        // Everyone S-1-1-0:  revision 1, 1 sub-authority, authority {0,0,0,0,0,1}, sub 0
        // SELF     S-1-5-10: revision 1, 1 sub-authority, authority {0,0,0,0,0,5}, sub 10
        if (sid.Length < 12 || sid[0] != 1 || sid[1] != 1)
            return false;

        if (sid[2] != 0 || sid[3] != 0 || sid[4] != 0 || sid[5] != 0 || sid[6] != 0)
            return false;

        var authority = sid[7];
        var subAuthority = BinaryPrimitives.ReadUInt32LittleEndian(sid.Slice(8, 4));

        return (authority == 1 && subAuthority == 0)
            || (authority == 5 && subAuthority == 10);
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
    /// Binds as the configured service account. A bind or connect failure here
    /// is a SERVICE-ACCOUNT failure and is routed through the shared
    /// <see cref="DirectoryErrorTranslator"/> with
    /// <see cref="DirectoryActor.ServiceAccount"/> — the same enforcement point
    /// the AD provider uses — so it always surfaces as an infrastructure error
    /// and can never be reported to the end user as invalid credentials. The
    /// underlying diagnosis is logged at Warning via
    /// <see cref="ServiceAccountFailure"/>; the wire response carries no server
    /// detail.
    /// </summary>
    /// <param name="correlationId">The request correlation ID, when available.</param>
    internal virtual LdapConnection BindAsServiceAccount(string? correlationId = null)
    {
        try
        {
            return Bind(_options.LdapUsername, _options.LdapPassword);
        }
        catch (LdapBindException ex)
        {
            // Bind rejected (wrong service-account credentials, the service
            // account locked/expired, etc.). Under ServiceAccount actor every
            // such end-user-account signal collapses to infrastructure.
            ServiceAccountFailure.Log(Logger, correlationId, "service-account bind", ServiceAccountHost(), ex);
            throw TranslateLdapException(
                (LdapException)ex.InnerException!, _options.ErrorDisclosureMode, DirectoryActor.ServiceAccount);
        }
        catch (DirectoryUnavailableException ex)
        {
            // No configured host could be reached: already infrastructure; add
            // the service-account diagnostic and rethrow unchanged.
            ServiceAccountFailure.Log(Logger, correlationId, "service-account connect", ServiceAccountHost(), ex);
            throw;
        }
    }

    private string ServiceAccountHost() =>
        _options.LdapHostnames.Length > 0
            ? string.Join(", ", _options.LdapHostnames)
            : "n/a";

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
            var ldap = LdapConnectionFactory();
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
    internal static Exception TranslateLdapException(LdapException ex, ErrorDisclosureMode disclosureMode) =>
        TranslateLdapException(ex, disclosureMode, DirectoryActor.User, out _);

    internal static Exception TranslateLdapException(
        LdapException ex,
        ErrorDisclosureMode disclosureMode,
        DirectoryActor actor) =>
        TranslateLdapException(ex, disclosureMode, actor, out _);

    internal static Exception TranslateLdapException(
        LdapException ex,
        ErrorDisclosureMode disclosureMode,
        out DirectoryFailureClass failureClass) =>
        TranslateLdapException(ex, disclosureMode, DirectoryActor.User, out failureClass);

    internal static Exception TranslateLdapException(
        LdapException ex,
        ErrorDisclosureMode disclosureMode,
        DirectoryActor actor,
        out DirectoryFailureClass failureClass)
    {
        var known = string.IsNullOrWhiteSpace(ex.LdapErrorMessage)
            ? null
            : ExtractWin32ErrorCode(ex.LdapErrorMessage);

        if (known is null)
        {
            failureClass = DirectoryFailureClass.Infrastructure;
            return new DirectoryUnavailableException(DirectoryErrorTranslator.DirectoryFailureMessage, ex);
        }

        failureClass = DirectoryErrorTranslator.ClassifyForActor(known.Code, actor);
        return DirectoryErrorTranslator.Translate(known.Code, disclosureMode, actor, ex);
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

    internal virtual ILdapSearchResults SearchLdap(
        LdapConnection ldap,
        string @base,
        int scope,
        string filter,
        string[] attrs,
        bool typesOnly,
        LdapSearchConstraints cons)
    {
        return ldap.Search(@base, scope, filter, attrs, typesOnly, cons);
    }

    private sealed record LdapUser(
        string DistinguishedName,
        IReadOnlyCollection<string> Groups,
        string? PrimaryGroupId);
}
