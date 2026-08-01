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
/// - No value interpolated into an LDAP search filter can alter that filter's
///   structure. This covers more than the submitted username: values read back
///   from the directory are not inert either, because RFC 4514 DN string form
///   escapes none of '(', ')' or '*'. Every filter value is therefore either
///   RFC 4515-escaped through <c>EscapeLdapSearchFilterValue</c> or validated to
///   a type that has no metacharacters to escape. (Search bases and modify
///   targets are deliberately not escaped this way — those are RFC 4514 DN
///   syntax, not RFC 4515 filter syntax.)
/// - Infrastructure failures never surface as auth or policy errors
/// </summary>
public class LdapPasswordChangeProvider : PasswordChangeProviderBase, IGroupMembershipTester, IGroupMembershipResolver, IPasswordLengthRequirement
{
    /// <inheritdoc />
    public override ErrorDisclosureMode ErrorDisclosureMode => _options.ErrorDisclosureMode;

    private readonly LdapPasswordChangeOptions _options;
    private readonly LdapSearchConstraints _searchConstraints;
    private readonly LdapRemoteCertificateValidationCallback? _certValidator;

    // The provider is registered as a singleton, so this is shared across requests —
    // which is the point: the value it holds is domain-wide, not per-account.
    private readonly CachedDomainMinimumLength _minimumLength = new();

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

    // Single wording for every way SanitizeUsername can reject its input, so the
    // rejections stay indistinguishable from one another on the wire.
    private const string InvalidUsernameFormatMessage = "Invalid username format";

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

    // Debug, deliberately, and unlike the group-enumeration failures that were
    // raised to Warning: this one really is a fallback. GetDomainNcRootFallback
    // derives the domain NC from the configured search base, the minimum-length
    // lookup continues, and a wrong answer here is still caught downstream by
    // DomainPasswordPolicy's own Warning (EventId 112) when the lookup as a whole
    // fails. Nothing is degraded silently, so this stays diagnostic detail.
    private static readonly Action<ILogger, Exception?> LogRootDseQueryFailed =
        LoggerMessage.Define(
            LogLevel.Debug,
            new EventId(107, nameof(LogRootDseQueryFailed)),
            "Failed to query defaultNamingContext from the rootDSE; falling back to deriving the " +
            "domain naming context from the configured LdapSearchBase. The minimum-length lookup " +
            "continues, and reports its own failure separately if the fallback does not resolve.");

    private static readonly Action<ILogger, string?, string, Exception?> LogNonNumericPrimaryGroupId =
        LoggerMessage.Define<string?, string>(
            LogLevel.Warning,
            new EventId(106, nameof(LogNonNumericPrimaryGroupId)),
            "primaryGroupID '{PrimaryGroupId}' on '{UserDn}' is not an integer RID, so the " +
            "account's primary group cannot be resolved. Group membership is therefore treated " +
            "as undetermined and the request is refused rather than being answered from an " +
            "incomplete picture. This is a directory-data problem: check the account's " +
            "primaryGroupID attribute.");

    private static readonly Action<ILogger, string, string, Exception?> LogGroupNotSecurityEnabled =
        LoggerMessage.Define<string, string>(
            LogLevel.Warning,
            new EventId(113, nameof(LogGroupNotSecurityEnabled)),
            "Configured group '{GroupName}' matched '{GroupDn}' by name, but that group is not " +
            "security-enabled, so it does not count as a membership. Only security groups are " +
            "matched: a distribution group carries no authorization anywhere else in Windows and " +
            "is frequently self-joinable. THIS CHANGES THE ANSWER — if the group is named in " +
            "RestrictedAdGroups the restriction is not being applied to this account, and if it " +
            "is named in AllowedAdGroups the account is not being admitted by it. Group type is " +
            "mutable, so check whether this group was converted from a security group.");

    // Debug, not Warning, and unlike LogGroupNotSecurityEnabled above: this one
    // really is a fallback. An unreadable group type degrades to the behaviour that
    // preceded the security-groups-only rule -- the group still matches -- so nothing
    // is refused that would previously have been allowed, and a deny list still
    // refuses. Raising it would make every non-AD directory log warnings for working
    // normally.
    private static readonly Action<ILogger, string, Exception?> LogGroupTypeUnreadable =
        LoggerMessage.Define<string>(
            LogLevel.Debug,
            new EventId(114, nameof(LogGroupTypeUnreadable)),
            "Could not read groupType for candidate group '{GroupDn}', so its type is treated as " +
            "absent and the group is still eligible to match. This is the same outcome as a " +
            "directory that publishes no groupType at all.");

    /// <summary>
    /// <c>ADS_GROUP_TYPE_SECURITY_ENABLED</c>: the high bit of <c>groupType</c>, set on
    /// every security group and clear on every distribution group.
    /// </summary>
    private const uint AdsGroupTypeSecurityEnabled = 0x80000000;

    private static readonly string[] RequiredAttributes =
    {
        "distinguishedName",
        "sAMAccountName",
        "memberOf",
        "primaryGroupID",
    };

    private static readonly string[] GroupTypeAttributes = { "groupType" };

    /// <summary>
    /// What a candidate group's <c>groupType</c> says about whether it may satisfy a
    /// configured group name.
    /// </summary>
    private enum GroupTypeClass
    {
        /// <summary>
        /// The directory does not publish <c>groupType</c> for this entry. Non-AD
        /// directories have no such attribute — an OpenLDAP <c>groupOfNames</c> carries
        /// nothing equivalent — so the group is treated as eligible. This is the
        /// documented fallback that keeps the provider working against non-AD servers;
        /// without it a security-only rule would match nothing at all there.
        /// </summary>
        Absent,

        /// <summary>Security-enabled, so it may satisfy a configured name.</summary>
        Security,

        /// <summary>A distribution group. It may not satisfy a configured name.</summary>
        Distribution,
    }

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

    /// <summary>
    /// Reports whether <paramref name="username"/> is a member of
    /// <paramref name="groupName"/>, directly, by primary group, or transitively.
    /// </summary>
    /// <remarks>
    /// <para><b>A negative answer means "determined not to be a member", never "could
    /// not tell".</b> A positive match is definitive the moment it is found, so every
    /// lookup below returns immediately on a hit and no later failure can affect it. A
    /// negative answer is only trustworthy if every lookup that could still have
    /// produced a match actually completed, so any lookup that fails is recorded and
    /// the method ends by throwing the shared infrastructure failure instead of
    /// returning <see langword="false"/>.</para>
    /// <para>This matters because the caller cannot distinguish the two outcomes from a
    /// <see langword="bool"/>. <c>GroupMembershipPolicy</c> evaluates
    /// <c>RestrictedAdGroups</c> as a deny list, so reporting "not a member" for a
    /// membership that could not be determined makes the deny list <em>fail open</em>:
    /// during a partial directory failure, a service-account permissions problem, or a
    /// cross-domain timeout, a member of <c>Domain Admins</c> would be allowed to change
    /// their password through this utility. Failing closed is the whole point of the
    /// deny list.</para>
    /// <para>Ordinary non-membership is unaffected and stays a plain
    /// <see langword="false"/>: a lookup that ran and matched nothing is a completed
    /// determination, and an empty result set is not a failure.</para>
    /// </remarks>
    public Task<bool> IsMemberOfGroupAsync(string username, string groupName)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(groupName);

        return IsMemberOfAnyGroup(username, new[] { groupName });
    }

    /// <summary>
    /// Resolves this user once so that every configured group name can be tested
    /// against the same resolution.
    /// </summary>
    /// <remarks>
    /// The per-group entry point above previously re-resolved the user for every
    /// name the policy asked about — with the shipped three restricted groups, three
    /// binds and three searches per unauthenticated request, before the caller had
    /// proved anything. The resolution is still lazy about the supplementary
    /// lookups: a name matched by direct <c>memberOf</c> never triggers them, which
    /// is the same short-circuit the per-group path always had.
    /// </remarks>
    public Task<IResolvedGroupMembership> ResolveMembershipAsync(string username)
    {
        ArgumentNullException.ThrowIfNull(username);

        return Task.FromResult<IResolvedGroupMembership>(new LdapResolvedMembership(this, username));
    }

    /// <summary>
    /// The membership evaluation itself, shared by the per-group and resolve-once
    /// entry points. Semantics are unchanged from the per-group version: a match is
    /// definitive, and a negative answer requires every lookup that could still have
    /// matched to have completed.
    /// </summary>
    private Task<bool> IsMemberOfAnyGroup(
        string username, IReadOnlyCollection<string> groupNames, LdapResolvedMembership? resolution = null)
    {
        if (groupNames.Count == 0)
            return Task.FromResult(false);

        try
        {
            // Resolved inside the try so that a failure here is translated exactly as
            // it always was, and cached on the resolution so a second evaluation of
            // the same request does not repeat it.
            var user = resolution?.User ?? FindUser(username);
            if (resolution is not null)
                resolution.User = user;

            // Records the first lookup that could not complete. Every match path
            // returns before reaching the end of the method, so a value here always
            // means "could not determine", never "determined not to be a member".
            Exception? undetermined = null;

            // A group can legitimately appear in BOTH the direct memberOf list and the
            // in-chain search results, so without this the same rejected group is
            // reported twice for one request. The warning is meant to tell an operator
            // that a configured name stopped matching; saying it twice per request
            // makes it look like two problems.
            var reportedNonSecurityGroups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            // 1. Direct membership check
            // `memberOf` returns full DNs (e.g. "cn=Admins,ou=groups,dc=example,dc=com").
            // Compare against the group's RDN value or its full DN, never as a substring,
            // so that "Admins" cannot accidentally match "AdminsExtra".
            //
            // A name match is a CANDIDATE, not yet an answer: only security groups
            // count, and `memberOf` yields DNs with no group-type information in them.
            // The type is therefore read per candidate DN — which happens only on the
            // match path, so the common negative answer costs nothing extra.
            foreach (var dn in user.Groups)
            {
                var matchedName = groupNames.FirstOrDefault(groupName => DnMatchesGroup(dn, groupName));
                if (matchedName is null)
                    continue;

                switch (ClassifyGroupByDn(dn))
                {
                    case GroupTypeClass.Security:
                    case GroupTypeClass.Absent:
                        return Task.FromResult(true);
                    case GroupTypeClass.Distribution:
                        // Not a match. Said out loud, because it changes the answer
                        // and group type is mutable.
                        if (reportedNonSecurityGroups.Add(dn))
                            LogGroupNotSecurityEnabled(Logger, matchedName, dn, null);
                        break;
                }
            }

            // 2. Primary Group Resolution (both well-known fallback and dynamic search)
            if (!string.IsNullOrEmpty(user.PrimaryGroupId))
            {
                // Robust check for well-known RIDs:
                if (user.PrimaryGroupId == "513" && groupNames.Any(g => g.Equals("Domain Users", StringComparison.OrdinalIgnoreCase)))
                    return Task.FromResult(true);
                if (user.PrimaryGroupId == "512" && groupNames.Any(g => g.Equals("Domain Admins", StringComparison.OrdinalIgnoreCase)))
                    return Task.FromResult(true);
                if (user.PrimaryGroupId == "519" && groupNames.Any(g => g.Equals("Enterprise Admins", StringComparison.OrdinalIgnoreCase)))
                    return Task.FromResult(true);

                // primaryGroupID is a RID, read back from the directory as a string.
                // Validating it as an integer is what keeps it inert in the filter
                // below: an integer has no RFC 4515 metacharacter to escape, so the
                // filter's structure cannot depend on the attribute's contents.
                if (int.TryParse(
                        user.PrimaryGroupId, NumberStyles.None, CultureInfo.InvariantCulture,
                        out var primaryGroupToken))
                {
                    try
                    {
                        using var ldap = BindAsServiceAccount();
                        var primaryFilter = FormattableString.Invariant(
                            $"(primaryGroupToken={primaryGroupToken})");
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
                            if (groupNames.Any(groupName => DnMatchesGroup(primaryDn, groupName)))
                                return Task.FromResult(true);
                        }
                    }
                    catch (Exception ex) when (ex is LdapException || ex is DirectoryUnavailableException)
                    {
                        // Not a fallback: the user's primary group is now unknown, so a
                        // "not a member" answer can no longer be justified.
                        undetermined ??= ex;
                        ServiceAccountFailure.Log(
                            Logger, correlationId: null, "resolve primary group by primaryGroupToken",
                            ServiceAccountHost(), ex);
                    }
                }
                else
                {
                    // The RID is unusable, so the primary group cannot be resolved for
                    // this account at all. That is the same outcome as a failed search —
                    // membership through the primary group is unknown, not absent.
                    // Treating it as absent would let a malformed attribute reopen the
                    // deny-list hole that the undetermined handling exists to close.
                    undetermined ??= new FormatException(
                        FormattableString.Invariant(
                            $"primaryGroupID '{user.PrimaryGroupId}' is not an integer RID."));
                    LogNonNumericPrimaryGroupId(
                        Logger, user.PrimaryGroupId, user.DistinguishedName, null);
                }
            }

            // 3. Transitive/Nested Group Resolution via LDAP_MATCHING_RULE_IN_CHAIN OID (Active Directory specific)
            try
            {
                using var ldap = BindAsServiceAccount();
                // The DN comes back from the directory, but it is not inert: RFC 4514
                // DN string form escapes none of '(', ')' or '*', so an account named
                // e.g. "CN=Smith (Contractor),OU=..." would otherwise produce a
                // malformed or structurally altered filter — and for a deny-list check
                // that means a wrong answer rather than a clean error.
                var chainFilter =
                    $"(member:1.2.840.113556.1.4.1941:={EscapeLdapSearchFilterValue(user.DistinguishedName)})";
                // groupType is requested alongside the DN, so the security-group rule
                // costs no extra round trip here. It is applied client-side rather than
                // as (groupType:1.2.840.113556.1.4.803:=2147483648) in the filter above
                // for two reasons: a server-side bit-AND cannot distinguish "this is a
                // distribution group" from "this directory has no groupType attribute",
                // which is exactly what the non-AD fallback turns on, and not every
                // directory implements the extensible match in the first place.
                var chainSearch = SearchLdap(
                    ldap,
                    _options.LdapSearchBase,
                    LdapConnection.ScopeSub,
                    chainFilter,
                    new[] { "distinguishedName", "groupType" },
                    false,
                    _searchConstraints);

                while (chainSearch.HasMore())
                {
                    var entry = chainSearch.Next();
                    var matchedName = groupNames.FirstOrDefault(groupName => DnMatchesGroup(entry.Dn, groupName));
                    if (matchedName is null)
                        continue;

                    switch (ClassifyGroupType(entry))
                    {
                        case GroupTypeClass.Security:
                        case GroupTypeClass.Absent:
                            return Task.FromResult(true);
                        case GroupTypeClass.Distribution:
                            if (reportedNonSecurityGroups.Add(entry.Dn))
                                LogGroupNotSecurityEnabled(Logger, matchedName, entry.Dn, null);
                            break;
                    }
                }
            }
            catch (Exception ex) when (ex is LdapException || ex is DirectoryUnavailableException)
            {
                // Nested membership is now unknown. Direct `memberOf` having
                // succeeded is not enough: it does not cover nesting, so it cannot
                // rule out a match this search would have found.
                undetermined ??= ex;
                ServiceAccountFailure.Log(
                    Logger, correlationId: null, "resolve transitive groups via LDAP_MATCHING_RULE_IN_CHAIN",
                    ServiceAccountHost(), ex);
            }

            // Nothing matched. That is only an answer if everything that could have
            // matched actually ran; otherwise this is "could not determine", and the
            // shared translator turns it into the infrastructure response rather than
            // letting it read as "not a member".
            if (undetermined is not null)
            {
                throw DirectoryErrorTranslator.TranslateException(
                    undetermined, _options.ErrorDisclosureMode, DirectoryActor.ServiceAccount);
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

    /// <inheritdoc />
    /// <remarks>
    /// Cached with a short time-to-live. This runs on every POST, before the caller
    /// has proved anything, and costs a bind plus two searches; the value is
    /// domain-wide and changes about as often as a group policy edit. Only a
    /// directory-sourced value is cached, so a failing lookup keeps re-attempting and
    /// keeps logging its warning.
    /// </remarks>
    public Task<int> GetMinimumLengthAsync()
    {
        return Task.FromResult(_minimumLength.Resolve(Logger, ReadMinPwdLength));
    }

    private int? ReadMinPwdLength()
    {
        using var ldap = BindAsServiceAccount();

        string domainNcRootDn = "";
        try
        {
            var rootDseSearch = SearchLdap(
                ldap,
                "",
                LdapConnection.ScopeBase,
                "(objectClass=*)",
                new[] { "defaultNamingContext" },
                false,
                _searchConstraints);

            if (rootDseSearch.HasMore())
            {
                var entry = rootDseSearch.Next();
                var attributeSet = entry.GetAttributeSet();
                var defaultNamingContextKey = attributeSet.Keys
                    .FirstOrDefault(k => k.Equals("defaultNamingContext", StringComparison.OrdinalIgnoreCase));
                if (defaultNamingContextKey != null)
                {
                    domainNcRootDn = attributeSet[defaultNamingContextKey].StringValue;
                }
            }
        }
        catch (Exception ex) when (ex is LdapException || ex is DirectoryUnavailableException)
        {
            LogRootDseQueryFailed(Logger, ex);
        }

        if (string.IsNullOrEmpty(domainNcRootDn))
        {
            domainNcRootDn = GetDomainNcRootFallback();
        }

        if (string.IsNullOrEmpty(domainNcRootDn))
            return null;

        var ncSearch = SearchLdap(
            ldap,
            domainNcRootDn,
            LdapConnection.ScopeBase,
            "(objectClass=*)",
            new[] { "minPwdLength" },
            false,
            _searchConstraints);

        if (ncSearch.HasMore())
        {
            var entry = ncSearch.Next();
            var attributeSet = entry.GetAttributeSet();
            var minPwdLengthKey = attributeSet.Keys
                .FirstOrDefault(k => k.Equals("minPwdLength", StringComparison.OrdinalIgnoreCase));
            if (minPwdLengthKey != null)
            {
                var valueStr = attributeSet[minPwdLengthKey].StringValue;
                if (int.TryParse(valueStr, out var minLength))
                    return minLength;
            }
        }

        return null;
    }

    private string GetDomainNcRootFallback()
    {
        var searchBase = _options.LdapSearchBase;
        if (string.IsNullOrEmpty(searchBase))
            return "";
        var dcIndex = searchBase.IndexOf("dc=", StringComparison.OrdinalIgnoreCase);
        return dcIndex >= 0 ? searchBase[dcIndex..] : searchBase;
    }

    /// <summary>
    /// Reads a candidate group's <c>groupType</c> by DN, for the direct-membership
    /// path where only the DN is known.
    /// </summary>
    /// <remarks>
    /// <para><b>A read that cannot complete yields <see cref="GroupTypeClass.Absent"/>,
    /// the same as a directory that publishes no <c>groupType</c>.</b> That is
    /// deliberate, and it is the one place in this file where a failure does not become
    /// "undetermined".</para>
    /// <para>The reasoning is the same one that motivated dropping the AD provider's
    /// second enumeration: a security-groups-only rule is a NARROWING of what may
    /// match, layered on a membership check that previously asked the directory
    /// nothing extra. If an unanswerable type question could refuse the request, this
    /// change would introduce a fresh environmental dependency capable of failing every
    /// request — precisely the fragility it exists to remove. Degrading to prior
    /// behaviour is strictly no worse than before the narrowing existed.</para>
    /// <para>It is also the safe direction for the case that matters. Treating an
    /// unreadable group as eligible means it still MATCHES, so a name in
    /// <c>RestrictedAdGroups</c> still refuses the request — the deny list stays
    /// closed. On the allow-list side it admits the account to the rest of the flow,
    /// where it must still prove the current password: exactly what it would have done
    /// before this change.</para>
    /// </remarks>
    private GroupTypeClass ClassifyGroupByDn(string dn)
    {
        try
        {
            using var ldap = BindAsServiceAccount();
            var search = SearchLdap(
                ldap,
                dn,
                LdapConnection.ScopeBase,
                "(objectClass=*)",
                GroupTypeAttributes,
                false,
                _searchConstraints);

            return search.HasMore() ? ClassifyGroupType(search.Next()) : GroupTypeClass.Absent;
        }
        catch (Exception ex) when (ex is LdapException || ex is DirectoryUnavailableException)
        {
            LogGroupTypeUnreadable(Logger, dn, ex);
            return GroupTypeClass.Absent;
        }
    }

    /// <summary>
    /// Classifies a group entry from its <c>groupType</c> attribute.
    /// </summary>
    /// <remarks>
    /// An absent or unparseable value yields <see cref="GroupTypeClass.Absent"/>, which
    /// is treated as eligible. That is the non-AD fallback: OpenLDAP's
    /// <c>groupOfNames</c> has no <c>groupType</c>, and a directory that publishes none
    /// would otherwise match no group at all.
    /// </remarks>
    private static GroupTypeClass ClassifyGroupType(LdapEntry entry)
    {
        var attributeSet = entry.GetAttributeSet();
        var groupTypeKey = attributeSet.Keys
            .FirstOrDefault(k => k.Equals("groupType", StringComparison.OrdinalIgnoreCase));

        if (groupTypeKey is null)
            return GroupTypeClass.Absent;

        var raw = attributeSet[groupTypeKey].StringValue;
        if (string.IsNullOrWhiteSpace(raw))
            return GroupTypeClass.Absent;

        // groupType is a 32-bit flags value that AD publishes as a SIGNED decimal, so
        // every security group arrives negative -- a global security group is
        // -2147483646 (0x80000002). Parsing as int and reinterpreting the bits is what
        // makes the high-bit test work on that form.
        if (!int.TryParse(raw.Trim(), NumberStyles.AllowLeadingSign, CultureInfo.InvariantCulture, out var parsed))
            return GroupTypeClass.Absent;

        return (unchecked((uint)parsed) & AdsGroupTypeSecurityEnabled) != 0
            ? GroupTypeClass.Security
            : GroupTypeClass.Distribution;
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
        var filter = BuildUserSearchFilter(username, _options.DefaultDomain, _options.LdapSearchFilter);

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

    /// <summary>
    /// Sanitizes <paramref name="username"/> and substitutes the result into the
    /// <c>{Username}</c> placeholder of <paramref name="searchFilterTemplate"/>.
    /// </summary>
    /// <remarks>
    /// A <c>sAMAccountName</c>-shaped filter matches the bare account name, never a
    /// qualified one, so a domain qualifier the sanitizer kept is dropped before
    /// substitution; a <c>userPrincipalName</c>-shaped filter keeps it. Split out from
    /// <see cref="FindUser"/> so the filter a given username and configuration produce
    /// can be asserted without a directory.
    /// </remarks>
    internal static string BuildUserSearchFilter(
        string username, string? defaultDomain, string searchFilterTemplate)
    {
        var safeUsername = SanitizeUsername(username, defaultDomain);

        var searchUsername = safeUsername;
        if (searchFilterTemplate.Contains("sAMAccountName", StringComparison.OrdinalIgnoreCase))
        {
            var atIdx = safeUsername.IndexOf('@', StringComparison.Ordinal);
            if (atIdx >= 0)
                searchUsername = safeUsername[..atIdx];
        }

        return searchFilterTemplate.Replace("{Username}", searchUsername, StringComparison.Ordinal);
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

    private static bool IsDomainMatching(string domainPart, string defaultDomain)
    {
        if (string.Equals(domainPart, defaultDomain, StringComparison.OrdinalIgnoreCase))
            return true;

        var dotIndex = defaultDomain.IndexOf('.', StringComparison.Ordinal);
        if (dotIndex > 0)
        {
            var prefix = defaultDomain[..dotIndex];
            if (string.Equals(domainPart, prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Produces a value safe to substitute into <see cref="LdapPasswordChangeOptions.LdapSearchFilter"/>:
    /// parses the domain and local parts explicitly, validates the qualifier against the configured
    /// <see cref="LdapPasswordChangeOptions.DefaultDomain"/>, and returns the escaped, canonicalized
    /// username.
    /// </summary>
    /// <remarks>
    /// <para>A configured <paramref name="defaultDomain"/> is authoritative: a bare name is qualified
    /// with it, a qualifier that matches it (the domain itself or its NetBIOS prefix) is canonicalized
    /// to it, and any other qualifier is rejected — a user of <c>other.com</c> must not be searched for
    /// in the configured domain.</para>
    /// <para>An empty <paramref name="defaultDomain"/> means there is no configured domain to validate a
    /// qualifier <em>against</em>, so a qualified name is accepted rather than rejected. Rejecting it
    /// makes the shipped configuration self-contradictory: it ships <c>DefaultDomain: ""</c> together
    /// with <c>UseEmail: true</c> and a username help block asking for an email address, so the exact
    /// input form the UI requests would come back as <c>InvalidCredentials</c> — indistinguishable from
    /// a wrong password, with nothing pointing at configuration. It would also diverge from the AD
    /// provider, whose <c>FixUsernameWithDomain</c> returns the supplied name unchanged when no default
    /// domain is configured and lets <c>FindByIdentity</c> resolve the UPN.</para>
    /// <para>In that unconfigured case a UPN suffix (<c>user@suffix</c>) is preserved, because it is
    /// meaningful to a <c>userPrincipalName</c>-shaped filter; a NetBIOS qualifier
    /// (<c>DOMAIN\user</c>) is dropped, because a NetBIOS name is not a UPN suffix and there is no
    /// configured domain to map it onto. Either way the account name itself still carries the full
    /// local-part validation below, and the returned value — including any preserved domain, which is
    /// user-supplied in this case — is escaped, so it stays inert in the filter.</para>
    /// <para>A backslash is a qualifier separator here, never part of an account name (the local-part
    /// rules reject one, since a <c>sAMAccountName</c> cannot contain it). So with no configured domain
    /// to check the qualifier against, any single-backslash input is read as <c>DOMAIN\account</c> —
    /// <c>a\b</c> resolves to account <c>b</c>. That is the only available reading: nothing
    /// distinguishes it from a genuine NetBIOS qualifier, and the account name it yields is still fully
    /// validated. With a <c>DefaultDomain</c> configured the qualifier must match it, so the same input
    /// is rejected.</para>
    /// </remarks>
    internal static string SanitizeUsername(string username, string? defaultDomain = null)
    {
        string localPart = username;
        string? domainPart = null;
        var netbiosQualified = false;

        var backslashIndex = username.IndexOf('\\', StringComparison.Ordinal);
        var atIndex = username.IndexOf('@', StringComparison.Ordinal);

        // A username is qualified in one syntax or the other. Something carrying
        // both separators is well-formed in neither, and would otherwise be split
        // on the backslash into two halves that are each meaningless — so it is
        // rejected outright, as it was in every configuration state before an
        // unvalidated qualifier could be accepted.
        if (backslashIndex >= 0 && atIndex >= 0)
            throw new InvalidCredentialsException(InvalidUsernameFormatMessage);

        if (backslashIndex >= 0)
        {
            domainPart = username[..backslashIndex];
            localPart = username[(backslashIndex + 1)..];
            netbiosQualified = true;
        }
        else if (atIndex >= 0)
        {
            domainPart = username[(atIndex + 1)..];
            localPart = username[..atIndex];
        }

        // The supplied qualifier is user input. Escaping (below) neutralizes the
        // RFC 4515 metacharacters; control characters are rejected outright, as
        // they are for the local part.
        if (!string.IsNullOrEmpty(domainPart) && domainPart.Any(char.IsControl))
            throw new InvalidCredentialsException(InvalidUsernameFormatMessage);

        if (string.IsNullOrEmpty(defaultDomain))
        {
            // Nothing is configured to validate the qualifier against, so it is
            // accepted: a UPN suffix is kept, a NetBIOS name is dropped.
            if (netbiosQualified)
                domainPart = null;
        }
        else
        {
            if (!string.IsNullOrEmpty(domainPart) && !IsDomainMatching(domainPart, defaultDomain))
                throw new InvalidCredentialsException(InvalidUsernameFormatMessage);

            // The configured domain is authoritative: it qualifies a bare name and
            // canonicalizes a matching NetBIOS prefix to the full domain.
            domainPart = defaultDomain;
        }

        if (localPart.Length == 0
            || localPart.Any(char.IsControl)
            || InvalidAccountNameCharsRegex.IsMatch(localPart))
        {
            throw new InvalidCredentialsException(InvalidUsernameFormatMessage);
        }

        var escapedLocalPart = EscapeLdapSearchFilterValue(localPart);
        return !string.IsNullOrEmpty(domainPart)
            ? $"{escapedLocalPart}@{EscapeLdapSearchFilterValue(domainPart)}"
            : escapedLocalPart;
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

    /// <summary>
    /// Holds one resolution of a user so that several group names can be tested
    /// against it without re-resolving. The user lookup happens once, on first use;
    /// each evaluation then reuses it.
    /// </summary>
    /// <remarks>
    /// Evaluation itself is deliberately not memoized. The supplementary lookups are
    /// skipped entirely whenever a name matches direct <c>memberOf</c>, which is the
    /// common case for a configured deny list, and preserving that short-circuit is
    /// worth more than collapsing the two calls the policy makes (restricted, then
    /// allowed) when a deployment configures both lists.
    /// </remarks>
    private sealed class LdapResolvedMembership : IResolvedGroupMembership
    {
        private readonly LdapPasswordChangeProvider _provider;
        private readonly string _username;

        public LdapResolvedMembership(LdapPasswordChangeProvider provider, string username)
        {
            _provider = provider;
            _username = username;
        }

        /// <summary>The resolved user, populated on first evaluation and reused after.</summary>
        internal LdapUser? User { get; set; }

        public Task<bool> IsMemberOfAnyAsync(IReadOnlyCollection<string> groupNames)
        {
            if (groupNames is null || groupNames.Count == 0)
                return Task.FromResult(false);

            return _provider.IsMemberOfAnyGroup(_username, groupNames, this);
        }
    }
}
