#if WINDOWS
using System.Runtime.Versioning;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using System.Threading.Tasks;
using System.Threading;
using System.Collections.Generic;

namespace Unosquare.PassCore.PasswordProvider
{
    /// <inheritdoc />
    /// <summary>
    /// Default Change Password Provider using 'System.DirectoryServices' from Microsoft.
    /// Implements the <see cref="IPasswordChangeProvider"/> interface to provide password change functionality
    /// against Active Directory using the System.DirectoryServices and System.DirectoryServices.AccountManagement namespaces.
    /// This implementation is intended for Windows platforms only.
    /// </summary>
    /// <seealso cref="IPasswordChangeProvider" />
    /// https://learn.microsoft.com/en-us/dotnet/fundamentals/code-analysis/quality-rules/ca1416#how-to-fix-violations
    [SupportedOSPlatform("windows")]
    public class PasswordChangeProvider : DirectoryPasswordChangeProviderBase
    {
        private readonly PasswordChangeOptions _options;

        private IdentityType _idType = IdentityType.UserPrincipalName;

        private static readonly Action<ILogger, Exception?> LogAdminResetIgnoredInAutomaticContext =
            LoggerMessage.Define(
                LogLevel.Warning,
                new EventId(103, nameof(LogAdminResetIgnoredInAutomaticContext)),
                "AllowAdministrativeReset is enabled but UseAutomaticContext is true, so it is " +
                "ignored: in automatic-context mode there is no service account to perform an " +
                "administrative reset with. Configure explicit LdapUsername/LdapPassword bind " +
                "credentials (UseAutomaticContext=false) if the fallback is wanted.");

        // Information, not a warning: skipping the sealed bind on the LDAPS port is
        // correct behaviour, not a degradation. It exists so that EventId 108
        // reporting "SSL" is not mistaken for sealing having been tried and refused
        // by the directory -- which is exactly the misreading that sent this
        // investigation after a non-existent fallback defect.
        private static readonly Action<ILogger, string, int, Exception?> LogSealedBindSkippedForLdapsPort =
            LoggerMessage.Define<string, int>(
                LogLevel.Information,
                new EventId(116, nameof(LogSealedBindSkippedForLdapsPort)),
                "Skipping the signed-and-sealed bind to {Host}: LdapPort is {Port}, the LDAPS port, " +
                "which is TLS from the first byte and cannot answer a plain LDAP bind. Connecting " +
                "over SSL instead. This is expected for an LDAPS configuration.");

        // EventId 117 (LogNoWorkingPasswordWritePath) is retired, not reused. It
        // told operators at startup that NO password change could succeed with
        // the AD provider on an explicit bind from a host that is not
        // domain-joined unless a domain controller was reachable over RPC/SMB,
        // and that enabling AllowAdministrativeReset would not rescue it.
        //
        // The second half was true of the code as it then stood and is no longer
        // true of it: the write now binds its own LDAPS entry, which works in
        // exactly the combination the warning declared hopeless. The first half
        // named the wrong remedy for the same reason -- RPC was where ADSI ended
        // up, not what it needed. Announcing a dead end that no longer exists,
        // and pointing at a firewall opening nobody needs, is worse than saying
        // nothing. What remains true -- that this path depends on LDAPS and
        // therefore on certificate trust -- is EventId 115's subject, and 119
        // reports it per-request when it actually bites.
        //
        // Warning, not error, and deliberately so. Everything on this path works
        // and is covered end-to-end against a live directory: reads, binds,
        // credential verification, group membership, minPwdLength, policy
        // evaluation, error routing, and now the password write itself. Refusing
        // to start would break deployments using all of that.
        //
        // The wording is scoped to what has been measured. On an entry bound
        // sign-and-seal on 389 from a host that is not domain-joined, the change
        // failed 0x80070547 (ERROR_CANT_ACCESS_DOMAIN_INFO) with the domain
        // controller recording no authentication attempt at all -- ADSI gave up
        // before contacting the directory, having no domain configuration to
        // read. On an LDAPS-bound entry, against the same directory in the same
        // run, both the change and the administrative reset succeeded, and the
        // directory recorded them as ordinary LDAP password modifications
        // attributed to the target user. That is why the requirement is stated as
        // LDAPS with a trusted certificate, and not as a domain join.
        //
        // What is deliberately NOT claimed: anything about a domain-joined host
        // running UseAutomaticContext=false. That combination remains untested,
        // in either direction.
        private static readonly Action<ILogger, Exception?> LogLdapsWriteRequired =
            LoggerMessage.Define(
                LogLevel.Warning,
                new EventId(115, nameof(LogLdapsWriteRequired)),
                "UseAutomaticContext is false, so password writes are performed over an LDAPS " +
                "connection this provider binds for the write. That REQUIRES the directory's " +
                "LDAPS port to be reachable and its certificate to be trusted by this machine; " +
                "nothing else on this path does, so a deployment can be entirely healthy today " +
                "and still fail here. If the LDAPS bind fails, the write falls back to a call " +
                "that chooses its own transport, which on a host that is NOT domain-joined has " +
                "been observed to fail with 0x80070547 (ERROR_CANT_ACCESS_DOMAIN_INFO) before " +
                "the directory is contacted at all, surfacing to the user as a generic " +
                "\"the directory service could not complete the password change request\". " +
                "That fallback is reported per-request at EventId 119 with the port and the " +
                "reason. Reads, credential verification, group membership, the minimum-length " +
                "lookup and policy evaluation do not use this connection and are unaffected. " +
                "RPC/SMB reachability is NOT required, and a domain join is not the remedy. " +
                "See TESTING.md, \"The AD password change on the explicit-bind path\".");

        // The WRITE channel, which is a different question from the
        // service-account context's channel (EventId 108) and is why these two
        // exist separately.
        //
        // IADsUser::ChangePassword and ::SetPassword both try LDAP over 128-bit
        // SSL, then Kerberos, then the Net* APIs over RPC, and which one they
        // reach is decided by the connection the DirectoryEntry is bound on.
        // Measured against a live directory from a host that is NOT
        // domain-joined: on an entry bound sign-and-seal on 389 the change fails
        // 0x80070547 and the reset falls through to RPC and fails 0x800706BA,
        // while on an LDAPS-bound entry in the same run against the same
        // directory both succeed. So the write is bound deliberately here rather
        // than inheriting whatever connection the principal carries.
        private static readonly Action<ILogger, string?, string, string, int, Exception?> LogPasswordWriteOverLdaps =
            LoggerMessage.Define<string?, string, string, int>(
                LogLevel.Information,
                new EventId(118, nameof(LogPasswordWriteOverLdaps)),
                "[{CorrelationId}] Performing the password {Operation} over an LDAPS-bound directory " +
                "entry at {Host}:{Port}. This is the transport the write itself uses; the " +
                "service-account context reported by EventId 108 is a separate connection.");

        // Names the port and the reason, because those are the two things that
        // decide what to do about it: an unreachable 636 is a firewall or a
        // directory that does not offer LDAPS, while a certificate failure is
        // trust on THIS machine. The exception carries the reason into the log
        // without putting it anywhere near the wire.
        //
        // Each placeholder appears EXACTLY ONCE. LoggerMessage.Define counts
        // occurrences, not distinct names, so repeating {Host} for emphasis
        // makes the count disagree with the type arguments and throws from the
        // static initializer -- taking the whole application down at startup,
        // not just this log line.
        private static readonly Action<ILogger, string?, string, string, int, Exception?> LogLdapsWriteBindFailed =
            LoggerMessage.Define<string?, string, string, int>(
                LogLevel.Warning,
                new EventId(119, nameof(LogLdapsWriteBindFailed)),
                "[{CorrelationId}] Could not bind an LDAPS directory entry for the password " +
                "{Operation} at {Host}:{Port}, so it falls back to the principal-based call, which " +
                "selects its own transport and has been observed to fail on a host that is not " +
                "domain-joined. That bind needs the port named above to be reachable on that host, " +
                "and the directory's certificate to be trusted by this machine. The reason is " +
                "attached.");

        // Records which channel the service-account context actually got. With a
        // fallback in the path, "it worked" is not enough information: an
        // operator debugging a password-change failure needs to know whether the
        // process is sealing or on SSL, and a deployment silently drifting from
        // one to the other is worth seeing.
        private static readonly Action<ILogger, string, string, int, Exception?> LogSecureChannelEstablished =
            LoggerMessage.Define<string, string, int>(
                LogLevel.Information,
                new EventId(108, nameof(LogSecureChannelEstablished)),
                "Service-account directory context established over {Channel} to {Host}:{Port}. " +
                "This is the channel for directory reads: lookups, credential verification, group " +
                "membership and the minimum-length policy. Password WRITES are not made through " +
                "it - they get their own LDAPS connection, reported at EventId 118.");

        private static readonly Action<ILogger, string, int, Exception?> LogSealingUnavailable =
            LoggerMessage.Define<string, int>(
                LogLevel.Warning,
                new EventId(109, nameof(LogSealingUnavailable)),
                "Could not establish a signed-and-sealed context to the directory; falling back to SSL " +
                "on {Host}:{Port}. The fallback needs the directory's certificate to be trusted by this " +
                "machine. If neither channel can be established, password changes will fail with an " +
                "access-denied error that describes the transport rather than any permission.");

        // EventId 105 (LogGroupEnumerationFallback) is retired, not reused. It
        // described a group-enumeration failure as an expected fallback logged at
        // Debug, which is no longer true in either direction: a failed enumeration
        // now leaves membership undetermined and fails the request closed, and it is
        // reported through ServiceAccountFailure (EventId 111) at Warning, like every
        // other service-account directory failure. Its message had also inverted
        // during an earlier refactor, naming the wrong call as the one that failed.

        // Warning, not a rejection: hard-failing startup over an IdTypeForUser typo
        // would break an existing deployment on upgrade, the same reasoning that
        // keeps the deprecated HideUserNotFound key (EventId 101, LDAP provider) a
        // warning rather than a startup failure.
        private static readonly Action<ILogger, string, IdentityType, Exception?> LogUnrecognizedIdentityType =
            LoggerMessage.Define<string, IdentityType>(
                LogLevel.Warning,
                new EventId(120, nameof(LogUnrecognizedIdentityType)),
                "IdTypeForUser '{IdTypeForUser}' is not a recognized identity type; falling back to " +
                "{FallbackType}. Recognized values are DistinguishedName, Guid, Name, SamAccountName, " +
                "Sid, and UserPrincipalName (and their common aliases). Correct the configuration if " +
                "the fallback is not what was intended.");

        // The resolved type is named twice, once in each half of the sentence, so both
        // halves read on their own. The two names differ because a structured payload
        // keys on the placeholder NAME: repeating one name emits a single property
        // whose second write clobbers the first, and a sink that rejects duplicate keys
        // has a malformed entry rather than a redundant one. The rendered sentence is
        // unaffected, since both placeholders receive the same value.
        //
        // Both must stay. LoggerMessage.Define counts placeholder OCCURRENCES, not
        // distinct names, and throws ArgumentException when that count disagrees with
        // the type-argument list — so two occurrences require the two type arguments
        // below, whatever the occurrences are called. This is what
        // LoggingConventionAuditTests.EveryLoggerMessageDefine_HasOneFormatPlaceholderPerTypeArgument
        // enforces across the repository; because these are static readonly fields, a
        // mismatch is a type-initialization failure at first use, not a compile error.
        private static readonly Action<ILogger, IdentityType, IdentityType, Exception?> LogIdentityTypeNotWebUsable =
            LoggerMessage.Define<IdentityType, IdentityType>(
                LogLevel.Warning,
                new EventId(121, nameof(LogIdentityTypeNotWebUsable)),
                "IdTypeForUser resolves to {IdentityType}, which cannot work from the web interface: " +
                "with {IdentityTypeRestated}, the submitted value is whatever the user typed rather " +
                "than a directory-verified identifier, so lookups will not resolve for ordinary " +
                "users. Use SamAccountName, Name, or UserPrincipalName instead.");

        /// <inheritdoc />
        /// <remarks>
        /// In automatic-context mode there is no service account bound with
        /// which to perform an administrative reset — <c>UserPrincipal.SetPassword</c>
        /// would run as the process identity instead, bypassing password
        /// history and minimum-age policy for a configuration EventId 103
        /// (<see cref="LogAdminResetIgnoredInAutomaticContext"/>) already tells
        /// operators at startup the fallback is ignored for. The fallback is
        /// therefore inert whenever <see cref="PasswordChangeOptions.UseAutomaticContext"/>
        /// is <see langword="true"/>, regardless of
        /// <see cref="PasswordChangeOptions.AllowAdministrativeReset"/>.
        /// </remarks>
        protected override bool AdministrativeResetSupported => !_options.UseAutomaticContext;

        public PasswordChangeProvider(
            ILogger<PasswordChangeProvider> logger,
            IOptions<PasswordChangeOptions> options,
            IOptions<ClientSettings> clientSettings,
            IEnumerable<IPasswordPolicy> policies)
            : base(logger, (options ?? throw new ArgumentNullException(nameof(options))).Value, !options.Value.UseAutomaticContext, clientSettings?.Value, policies)
        {
            _options = options.Value;
            SetIdType();

            if (_options.AllowAdministrativeReset && _options.UseAutomaticContext)
                LogAdminResetIgnoredInAutomaticContext(Logger, null);

            // Told to the operator at startup rather than to the user at failure.
            // The certificate trust this path depends on is exercised by nothing
            // else PassCore does, so without this the first sign of a missing or
            // untrusted certificate is an end user receiving a generic directory
            // error from a deployment whose every other operation is healthy.
            if (!_options.UseAutomaticContext)
                LogLdapsWriteRequired(Logger, null);
        }

        /// <inheritdoc />
        /// <remarks>
        /// Directory failures are routed through
        /// <see cref="DirectoryErrorTranslator"/> so this provider and the LDAP
        /// provider report identical conditions identically. How much a failure
        /// discloses (user-not-found, account state) is controlled by the
        /// <see cref="IAppSettings.ErrorDisclosureMode"/> setting shared by both
        /// providers; see <see cref="ErrorDisclosureMode"/> for the trade-off.
        /// </remarks>
        protected override async Task ChangeDirectoryPasswordCore(PasswordChangeContext context, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(context);

            var fixedUsername = FixUsernameWithDomain(context.Username);

            // Acquiring the context and resolving the user are SERVICE-ACCOUNT
            // operations: a failure here (bad bind credentials, unreachable DC)
            // describes the application's own connection, never the end user's
            // password. RunAsServiceAccount guarantees it surfaces as an
            // infrastructure failure, so it can't be misreported as invalid
            // credentials. A *successful* lookup that finds no user still
            // returns null (not an exception) and remains UserNotFound below.
            using var principalContext = RunAsServiceAccount(
                "acquire principal context", context.CorrelationId, AcquirePrincipalContext);
            var userPrincipal = RunAsServiceAccount(
                "resolve user by identity", context.CorrelationId,
                () => UserPrincipal.FindByIdentity(principalContext, _idType, fixedUsername));

            if (userPrincipal == null) // Check if UserPrincipal is null
            {
                // Posture-aware existence handling shared with the LDAP provider.
                throw DirectoryErrorTranslator.CreateUserNotFoundError(_options.ErrorDisclosureMode);
            }

            // NOTHING may write to the directory above this line. Everything
            // before it runs for a caller who has supplied only a username,
            // so a write here would be an unauthenticated modification. (A
            // pre-flight 'pwdLastSet' write used to sit exactly here; see
            // docs/UPGRADING-error-routing.md.) Directory writes belong
            // after verification: ChangePassword / SetPassword / Save below.
            var verificationIdentifier = userPrincipal.UserPrincipalName ?? userPrincipal.SamAccountName ?? fixedUsername;
            if (!ValidateUserCredentials(verificationIdentifier, context.CurrentPassword, principalContext, out var verificationCode)) // Validate provided current password
            {
                // The wire message is unchanged and carries no detail. The
                // reason travels as the INNER exception only, so the base
                // class's existing failure log (EventId 4) records it with
                // the correlation ID while the caller still learns nothing
                // — the compensating control for hardened mode collapsing
                // every credential/account-state condition into one
                // response. This mirrors the LDAP provider, which passes
                // its LdapBindException the same way.
                var detail = CredentialFailureDetail.ForWin32Code(verificationCode);

                throw detail == null
                    ? new InvalidCredentialsException(DirectoryErrorTranslator.InvalidCredentialsMessage)
                    : new InvalidCredentialsException(DirectoryErrorTranslator.InvalidCredentialsMessage, detail);
            }

            // The cannot-change check runs strictly AFTER credential
            // verification: before, it disclosed account existence and flag
            // state to unauthenticated callers even in hardened mode. The
            // verified flags below are derived from control flow — these
            // lines are reachable only after ValidateUserCredentials
            // returned true.
            if (userPrincipal.UserCannotChangePassword)
            {
                await HandleCannotChangePassword(context, userPrincipal, currentPasswordVerified: true).ConfigureAwait(false);
            }
            else
            {
                await UpdatePassword(context, userPrincipal, currentPasswordVerified: true).ConfigureAwait(false);
            }

            // No userPrincipal.Save() here. Nothing in this provider ever assigns a
            // property on the principal, and every write path commits on its own:
            // ChangePassword/SetPassword apply immediately, and the LDAPS paths write
            // through the separate DirectoryEntry that BindForWrite returns, not
            // through this object. A Save() would therefore have nothing to persist —
            // it was left behind by the removed pre-flight 'pwdLastSet' write (see
            // docs/UPGRADING-error-routing.md).
        }

        /// <summary>
        /// Resolves this user's group names once so that every configured group name
        /// can be tested against the same resolution.
        /// </summary>
        /// <remarks>
        /// <para>The per-group entry point above previously re-ran the whole sequence —
        /// a fresh <c>PrincipalContext</c>, a <c>FindByIdentity</c>, and
        /// <c>GetAuthorizationGroups</c> (the expensive one) — for every name the policy
        /// asked about. With the shipped three restricted groups that is three of each,
        /// per unauthenticated request, before the caller has proved anything.</para>
        /// <para>The enumeration is materialized into plain names in a single pass so
        /// that the <c>PrincipalContext</c> and <c>UserPrincipal</c> can be disposed
        /// immediately rather than held open across the policy's evaluation.</para>
        /// </remarks>
        public override Task<IResolvedGroupMembership> ResolveMembershipAsync(string username)
        {
            // Every operation here is a service-account directory read (context,
            // resolve, group enumeration); a failure is infrastructure, never an
            // end-user credential signal. There is no request context here, so the
            // correlation ID is unavailable — the base class logs the propagated
            // failure with the correlation ID as a backstop.
            try
            {
                using var principalContext = RunAsServiceAccount(
                    "acquire principal context", correlationId: null, AcquirePrincipalContext);
                var userPrincipal = RunAsServiceAccount(
                    "resolve user by identity", correlationId: null,
                    () => UserPrincipal.FindByIdentity(principalContext, _idType, FixUsernameWithDomain(username)));

                // Matches FindUser in the LDAP provider (and this provider's own
                // password-change path, above) for the identical condition: an
                // unresolvable user is UserNotFound, not "resolved with no
                // groups". The dedicated "no such user" resolution value this used
                // to return let GroupMembershipPolicy read an unknown user as "not
                // in AllowedAdGroups" and report CreateGroupRejectionError
                // (ChangeNotPermitted, 6) instead — the same condition the LDAP
                // provider reports as UserNotFound (3) in Informative mode. Hardened
                // mode is unaffected: both errors already collapse to
                // InvalidCredentials there, so only Informative disclosure changes.
                if (userPrincipal == null)
                    throw DirectoryErrorTranslator.CreateUserNotFoundError(_options.ErrorDisclosureMode);

                // Records the first enumeration that could not complete. A match is
                // still definitive, so this only decides what a *negative* answer
                // means: "determined not to be a member", or "could not determine".
                Exception? undetermined = null;
                var groupNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                // GetAuthorizationGroups is the SOLE match source. It reads tokenGroups
                // -- one base-scope read the DC computes -- and returns the complete
                // transitive security-group closure, including the primary group.
                //
                // GetGroups() used to be unioned in here and has been removed. What it
                // added over this call is distribution groups, which cannot enter a
                // Windows access token and therefore cannot carry authorization; see
                // the class remarks on group-type semantics. What it cost was
                // Forest.GetForest() -- full forest topology discovery ending in a bind
                // over the GC:// provider -- on every unauthenticated request, whose
                // failure made every NEGATIVE answer undetermined. That is a wide blast
                // radius for a source that could only ever contribute groups this
                // provider must not honour.
                try
                {
                    using var authGroups = userPrincipal.GetAuthorizationGroups();
                    CollectNames(authGroups, groupNames);
                }
                catch (Exception ex)
                {
                    // Membership is now unknown, and nothing else covers this ground.
                    // The undetermined handling below is unchanged and deliberately so:
                    // a failed enumeration still fails the request closed rather than
                    // reporting "not a member".
                    undetermined ??= ex;
                    ServiceAccountFailure.Log(
                        Logger, correlationId: null, "enumerate authorization groups",
                        ServiceAccountHost(), ex);
                }

                // The enumeration is already materialized, so evaluation is pure
                // in-memory matching. A match is definitive regardless of what else
                // failed; only a NEGATIVE answer depends on everything having run.
                return Task.FromResult(ResolveMembership(requested =>
                    Task.FromResult(
                        requested.Any(groupNames.Contains) ? GroupMembershipAnswer.Member
                        : undetermined is null ? GroupMembershipAnswer.NotMember
                        : GroupMembershipAnswer.Undetermined(undetermined))));
            }
            catch (PasswordChangeException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Group enumeration failed: a service-account directory read, so
                // translate as ServiceAccount — never as end-user credentials.
                ServiceAccountFailure.Log(Logger, correlationId: null, "read group membership", ServiceAccountHost(), ex);
                throw DirectoryErrorTranslator.TranslateException(
                    ex, _options.ErrorDisclosureMode, DirectoryActor.ServiceAccount);
            }
        }

        /// <summary>
        /// Copies a principal collection's names into <paramref name="into"/>. A group
        /// that cannot be reduced to a name means the enumeration cannot be trusted to
        /// rule anything out, so it throws and is recorded as undetermined by the
        /// caller rather than being silently skipped — dropping it could turn a
        /// deny-list match into a miss.
        /// </summary>
        private static void CollectNames(IEnumerable<Principal> principals, HashSet<string> into)
        {
            foreach (var principal in principals)
            {
                // The null ELEMENT is the case that actually occurs, not a non-null
                // principal with a null Name: GetAuthorizationGroups yields nulls for
                // SIDs it cannot translate (dotnet/runtime#80675). Testing
                // principal?.Name rather than principal.Name is what keeps that on the
                // intended path -- the outcome is fail-closed either way, but through
                // this explanatory exception instead of a bare NullReferenceException.
                // It matters more now that this is the only enumeration left.
                into.Add(principal?.Name ?? throw new InvalidOperationException(
                    "A group principal has no Name, so this enumeration cannot rule out membership."));
            }
        }

        /// <summary>
        /// Validates the user's current credentials against Active Directory.
        /// Attempts to validate using PrincipalContext.ValidateCredentials first, and falls back to LogonUser if necessary.
        /// </summary>
        /// <param name="upn">The User Principal Name of the user.</param>
        /// <param name="currentPassword">The current password provided by the user.</param>
        /// <param name="principalContext">The PrincipalContext to use for validation.</param>
        /// <param name="win32Code">Receives the Win32 code reported by the failed
        /// logon, or <c>0</c> when the credentials validated without one. It exists
        /// purely so the caller can attach the reason to the log; it takes no part
        /// in the decision this method returns.</param>
        /// <returns>True if credentials are valid, or if the error code indicates password must be changed or is expired, otherwise false.</returns>
        private bool ValidateUserCredentials(
            string upn,
            string currentPassword,
            PrincipalContext principalContext,
            out int win32Code)
        {
            win32Code = 0;

            if (string.IsNullOrEmpty(upn))
            {
                win32Code = 1326; // ERROR_LOGON_FAILURE
                return false;
            }

            if (principalContext.ValidateCredentials(upn, currentPassword)) // First attempt: Validate credentials using PrincipalContext
            {
                return true; // Credentials validated successfully
            }

            // Fallback validation using LogonUser (more comprehensive but potentially less performant)
            if (NativeMethods.LogonUser(upn, string.Empty, currentPassword, NativeMethods.LogonTypes.Network, NativeMethods.LogonProviders.Default, out var token))
            {
                using (token)
                {
                    return true; // LogonUser succeeded, credentials validated
                }
            }

            // Check for specific error codes indicating password expiration or must change scenarios
            win32Code = System.Runtime.InteropServices.Marshal.GetLastWin32Error(); // Get the last Win32 error code

            // Expired / must-change-at-next-logon still proves the user knows the current
            // password; the shared classification keeps this decision identical to the
            // LDAP provider's bind handling.
            return DirectoryErrorTranslator.IsPasswordExpiredOrMustChange(win32Code);
        }

        /// <summary>
        /// Fixes the username by appending the default domain if the username is in simple format and IdentityType is UserPrincipalName.
        /// </summary>
        /// <param name="username">The username to fix.</param>
        /// <returns>The fixed username, potentially with the default domain appended.</returns>
        /// <remarks>
        /// <para>Non-<see cref="IdentityType.UserPrincipalName"/> identity types are returned
        /// unchanged, with no validation: <see cref="IdentityType.DistinguishedName"/>,
        /// <see cref="IdentityType.Guid"/>, <see cref="IdentityType.Sid"/> and
        /// <see cref="IdentityType.SamAccountName"/> lookups behave exactly as before.</para>
        /// <para>On the <see cref="IdentityType.UserPrincipalName"/> path this now routes through
        /// the shared <see cref="UsernameQualifier"/>, so a qualifier that does not match
        /// <see cref="PasswordChangeOptions.DefaultDomain"/> (e.g. <c>user@other.com</c> against a
        /// configured <c>corp.local</c>) or a control character in the qualifier is refused with
        /// <see cref="DirectoryErrorTranslator.InvalidCredentialsMessage"/> rather than being handed
        /// to <c>FindByIdentity</c> unexamined. A bare name is still qualified with the configured
        /// domain, and a matching qualifier (the domain itself or its NetBIOS prefix) is
        /// canonicalized to it — the same policy the LDAP provider's <c>SanitizeUsername</c>
        /// applies, so a mismatched domain qualifier or a control character in the qualifier is
        /// rejected identically by both providers. <b>Only the qualifier is validated
        /// identically</b>: <see cref="UsernameQualifier.Resolve"/> never inspects the local part,
        /// so this method adds its own control-character check for it, below — the LDAP provider's
        /// equivalent rejection (empty local part, control characters,
        /// <c>InvalidAccountNameCharsRegex</c>) is not reproduced here beyond that one check.</para>
        /// <para><b>This also changes what a NetBIOS-qualified (<c>DOMAIN\user</c>) username
        /// resolves to</b>, which the old append-only code had no concept of at all:
        /// <c>CORP\jdoe</c> with <c>DefaultDomain=corp.local</c> now resolves to
        /// <c>jdoe@corp.local</c> (previously <c>CORP\jdoe</c>, handed to <c>FindByIdentity</c>
        /// unexamined); <c>CORP\jdoe</c> or <c>OTHER\jdoe</c> with no <c>DefaultDomain</c>
        /// configured now resolves to bare <c>jdoe</c> (previously <c>CORP\jdoe</c> /
        /// <c>OTHER\jdoe</c> respectively) — an unmatched NetBIOS qualifier is DROPPED, not kept,
        /// when there is no configured domain to validate or canonicalize it against. This is
        /// deliberate, not incidental: it is what makes this provider agree with the LDAP
        /// provider's qualifier handling, which is the point of routing through the shared
        /// helper.</para>
        /// </remarks>
        private string FixUsernameWithDomain(string username)
        {
            if (_idType != IdentityType.UserPrincipalName) return username; // No fixing needed if IdentityType is not UserPrincipalName

            var qualified = UsernameQualifier.Resolve(
                username, _options.DefaultDomain, DirectoryErrorTranslator.InvalidCredentialsMessage);

            // UsernameQualifier.Resolve validates only the qualifier; the local part is
            // its caller's concern. A control character here reaches FindByIdentity
            // unexamined otherwise -- unlike ',' or '=', a control character cannot be
            // part of a legitimate DistinguishedName-style identity, so this check is
            // safe to add without reopening the DN concern that keeps the fuller
            // sAMAccountName rules in the LDAP provider.
            if (qualified.LocalPart.Any(char.IsControl))
                throw new InvalidCredentialsException(DirectoryErrorTranslator.InvalidCredentialsMessage);

            return string.IsNullOrEmpty(qualified.DomainPart)
                ? qualified.LocalPart
                : $"{qualified.LocalPart}@{qualified.DomainPart}";
        }

        /// <summary>
        /// Updates the user's password in Active Directory with a user-context
        /// ChangePassword. On failure, an administrative SetPassword fallback
        /// may fire — but only when <see cref="PasswordChangeOptions.AllowAdministrativeReset"/>
        /// is enabled (default off), the user's current password was verified in
        /// this request, the failure is the cannot-change-password condition
        /// (<see cref="DirectoryFailureClass.ChangeNotPermitted"/> — the only
        /// class the shared <see cref="AdministrativeReset"/> gate rescues;
        /// new-password policy rejections such as history or minimum age are
        /// deliberately excluded so intentional domain policy is never bypassed),
        /// and the provider is bound with service-account credentials
        /// (automatic-context mode never resets). Every reset is logged at
        /// Warning with the request correlation ID. With the fallback disabled
        /// or ineligible, the failure surfaces through
        /// <see cref="DirectoryErrorTranslator"/> like any other change failure.
        /// </summary>
        /// <param name="context">The password change context.</param>
        /// <param name="userPrincipal">The UserPrincipal object for the user.</param>
        /// <param name="currentPasswordVerified">Whether the current password was verified in this request.</param>
        private Task UpdatePassword(
            PasswordChangeContext context,
            AuthenticablePrincipal userPrincipal,
            bool currentPasswordVerified)
        {
            // The old password is still supplied and still verified by the
            // directory, whichever channel this takes: this is a genuine
            // change, not a reset wearing its name. History and minimum-age
            // policy therefore keep applying, which is the whole reason the
            // reset is a separate, gated, loudly-logged thing. Both closures'
            // bodies are the EXISTING write calls, unchanged, and stay in this
            // file — see the remarks on PerformGatedPasswordWrite for why that
            // matters to AdProviderDirectoryWriteAuditTests.
            return PerformGatedPasswordWrite(
                context,
                currentPasswordVerified,
                writeChangeAsUser: () =>
                {
                    using var entry = BindForWrite(context.CorrelationId, "change", userPrincipal);

                    if (entry is null)
                        userPrincipal.ChangePassword(context.CurrentPassword, context.NewPassword);
                    else
                        entry.Invoke("ChangePassword", new object[] { context.CurrentPassword, context.NewPassword });

                    return Task.CompletedTask;
                },
                writeResetAsService: () =>
                {
                    PerformAdministrativeReset(context, userPrincipal);
                    return Task.CompletedTask;
                });
        }

        /// <summary>
        /// Post-verification handling for accounts whose
        /// <see cref="AuthenticablePrincipal.UserCannotChangePassword"/> flag is
        /// set: routes the synthesized
        /// <see cref="DirectoryFailureClass.ChangeNotPermitted"/> through the
        /// same shared gate as modify-time failures. Eligible: performs the
        /// administrative reset directly (the user-context ChangePassword is
        /// doomed and is not attempted). Not eligible: throws the translator's
        /// curated ChangeNotPermitted error, identical to the LDAP provider's
        /// wording. Never resets in automatic-context mode.
        /// </summary>
        /// <param name="context">The password change context.</param>
        /// <param name="userPrincipal">The UserPrincipal object for the user.</param>
        /// <param name="currentPasswordVerified">Whether the current password was verified in this request.</param>
        private Task HandleCannotChangePassword(
            PasswordChangeContext context,
            AuthenticablePrincipal userPrincipal,
            bool currentPasswordVerified)
        {
            // The user-context ChangePassword is doomed for this account and
            // must not be attempted: PerformGatedBlockedWrite goes straight to
            // the gate and, if eligible, the reset closure below.
            return PerformGatedBlockedWrite(
                context,
                currentPasswordVerified,
                writeResetAsService: () =>
                {
                    PerformAdministrativeReset(context, userPrincipal);
                    return Task.CompletedTask;
                });
        }

        /// <summary>
        /// The single reset execution path: an administrative SetPassword over
        /// an LDAPS-bound entry for the target user, falling back to the
        /// principal-based call when that entry cannot be bound. Reached only
        /// through the <see cref="AdministrativeReset"/> gate via
        /// <c>PerformGatedPasswordWrite</c>, which logs the reset itself
        /// once this closure returns.
        /// </summary>
        /// <param name="context">The password change context.</param>
        /// <param name="userPrincipal">The UserPrincipal object for the user.</param>
        private void PerformAdministrativeReset(
            PasswordChangeContext context,
            AuthenticablePrincipal userPrincipal)
        {
            using var entry = BindForWrite(context.CorrelationId, "reset", userPrincipal);

            if (entry is null)
                userPrincipal.SetPassword(context.NewPassword);
            else
                entry.Invoke("SetPassword", new object[] { context.NewPassword });
        }

        /// <summary>
        /// Binds a <see cref="DirectoryEntry"/> for the target user over LDAPS,
        /// so that a password write goes out on a connection this provider chose
        /// rather than on whichever one the <see cref="AuthenticablePrincipal"/>
        /// happens to be carrying. Returns <see langword="null"/> when no such
        /// entry can be bound, which tells the caller to make the ordinary
        /// principal-based call instead.
        /// </summary>
        /// <remarks>
        /// <para><b>Why the write gets its own connection.</b> Both
        /// <c>IADsUser::ChangePassword</c> and <c>IADsUser::SetPassword</c> try
        /// LDAP over 128-bit SSL first, then Kerberos, then the <c>Net*</c> APIs
        /// over RPC, and the connection the entry is bound on decides how far
        /// down that list they get. Measured from a host that is not
        /// domain-joined, against the same directory in the same run: on an entry
        /// bound sign-and-seal on 389, the change failed with <c>0x80070547</c>
        /// having never contacted the directory and the reset fell through to RPC
        /// and failed <c>0x800706BA</c>; on an LDAPS-bound entry, both succeeded,
        /// and the directory recorded them as ordinary LDAP password
        /// modifications attributed to the target user.</para>
        /// <para><b>Only the write.</b> The service-account context is
        /// deliberately left alone — it leads with sign-and-seal, which needs no
        /// certificate trust, and imposing LDAPS on every read to fix the write
        /// would make certificate trust a prerequisite for operations that do not
        /// need it. LDAPS is required only where it is the difference between
        /// working and not.</para>
        /// <para><b>The port is not configurable separately</b>, and deliberately:
        /// it comes from <see cref="LdapChannelPorts.SslPortFor(int)"/>, the same
        /// substitution the SSL fallback in <see cref="AcquirePrincipalContext"/>
        /// already uses. A deployment on the default 389 gets 636; a deployment
        /// that has moved LDAPS elsewhere and set <c>LdapPort</c> to it gets that
        /// value as given.</para>
        /// <para><b>Automatic-context deployments are untouched.</b> There are no
        /// bind credentials there to build an entry with, and nothing is known to
        /// be wrong with that path.</para>
        /// </remarks>
        /// <param name="correlationId">The request correlation ID, for the log.</param>
        /// <param name="operation">"change" or "reset", named in the log so the
        /// two writes are distinguishable.</param>
        /// <param name="userPrincipal">The user whose password is being written.</param>
        /// <returns>A bound entry, or <see langword="null"/> to fall back.</returns>
        private DirectoryEntry? BindForWrite(
            string? correlationId,
            string operation,
            AuthenticablePrincipal userPrincipal)
        {
            if (_options.UseAutomaticContext)
                return null;

            var host = _options.LdapHostnames.FirstOrDefault();
            var distinguishedName = userPrincipal.DistinguishedName;

            // Neither is expected to be missing here — the options are validated
            // at startup and the principal was resolved from the directory — but
            // a null path or DN would throw out of a method whose contract is
            // "returns null when it cannot bind", which the caller would then
            // report as a change failure rather than falling back.
            if (string.IsNullOrWhiteSpace(host) || string.IsNullOrWhiteSpace(distinguishedName))
                return null;

            var port = LdapChannelPorts.SslPortFor(_options.LdapPort);
            DirectoryEntry? entry = null;

            try
            {
                entry = new DirectoryEntry(
                    AdsiPath.ForObject(host, port, distinguishedName),
                    _options.LdapUsername,
                    _options.LdapPassword,
                    AuthenticationTypes.Secure | AuthenticationTypes.SecureSocketsLayer);

                // DirectoryEntry binds lazily, so without this the bind failure
                // would surface from Invoke instead — where it is indistinguishable
                // from the password write itself being rejected, and where falling
                // back would mean retrying a change the directory already refused.
                // Reading one attribute the object certainly has forces the bind
                // and nothing else.
                entry.RefreshCache(new[] { "distinguishedName" });

                LogPasswordWriteOverLdaps(Logger, correlationId, operation, host, port, null);
                return entry;
            }
            catch (Exception bindFailure)
            {
                entry?.Dispose();
                LogLdapsWriteBindFailed(Logger, correlationId, operation, host, port, bindFailure);
                return null;
            }
        }

        /// <summary>
        /// Sets the identity type based on configuration options, providing fault tolerance for various string inputs.
        /// The alias table and fallback live in <see cref="UserIdentityTypeClassifier"/> so they can be exercised
        /// cross-platform; this method only maps the shared <see cref="UserIdentityType"/> result onto the
        /// Windows-only <see cref="IdentityType"/> and logs when the configuration deserves a warning.
        /// </summary>
        private void SetIdType()
        {
            var resolved = UserIdentityTypeClassifier.Classify(
                _options.IdTypeForUser, out var recognized, out var usableInWebInterface);

            _idType = resolved switch
            {
                UserIdentityType.DistinguishedName => IdentityType.DistinguishedName,
                UserIdentityType.GuidValue => IdentityType.Guid,
                UserIdentityType.Name => IdentityType.Name,
                UserIdentityType.SamAccountName => IdentityType.SamAccountName,
                UserIdentityType.Sid => IdentityType.Sid,
                _ => IdentityType.UserPrincipalName
            };

            // recognized is false only when IdTypeForUser was present, non-blank,
            // and matched no known alias -- absent/null/blank is a legitimate
            // request for the default and must not warn.
            if (!recognized)
                LogUnrecognizedIdentityType(Logger, _options.IdTypeForUser ?? string.Empty, _idType, null);

            if (!usableInWebInterface)
                LogIdentityTypeNotWebUsable(Logger, _idType, _idType, null);
        }

        /// <summary>
        /// Describes the directory host used for service-account operations,
        /// for diagnostics logging only.
        /// </summary>
        /// <remarks>
        /// Overrides the base's "join every configured host" default because
        /// this provider binds a single host, not several tried in turn: in
        /// automatic-context mode there is no configured host at all, and
        /// otherwise only the first hostname is ever actually used (see
        /// <see cref="AcquirePrincipalContext"/> and <see cref="BindForWrite"/>),
        /// so naming the rest would misdescribe the connection.
        /// </remarks>
        protected override string ServiceAccountHost() =>
            _options.UseAutomaticContext
                ? "automatic domain context"
                : _options.LdapHostnames.FirstOrDefault() ?? "n/a";

        /// <summary>
        /// Acquires a PrincipalContext object for Active Directory operations.
        /// If 'UseAutomaticContext' is enabled, it uses the automatic domain context.
        /// Otherwise, it creates a context based on LDAP hostname, port, username, and password from options.
        /// Throws an exception if PrincipalContext cannot be acquired when not using automatic context.
        /// </summary>
        /// <returns>A <see cref="PrincipalContext"/> object for Active Directory interaction.</returns>
        /// <exception cref="InvalidOperationException">Thrown if LDAP Hostnames are not configured when not using automatic context, or if PrincipalContext creation fails.</exception>
        private PrincipalContext AcquirePrincipalContext()
        {
            if (_options.UseAutomaticContext) // Check if automatic context is enabled
            {
                return new PrincipalContext(ContextType.Domain); // Create PrincipalContext using automatic domain context
            }
            else
            {
                // No LdapHostnames-empty guard here: the constructor already ran
                // AppSettingsValidation.ValidateServiceAccount(opts, required:
                // !UseAutomaticContext) (see ValidateOptions, :248), which is the
                // single point enforcing that LdapHostnames is non-empty whenever
                // UseAutomaticContext is false. Reaching this branch implies that
                // check ran and passed.
                var host = _options.LdapHostnames.First();

                // The sign-and-seal flags below are EXPLICIT, not new. The
                // four-argument PrincipalContext constructor this replaced
                // chained to GetDefaultOptionForStore(Domain), which is already
                // Negotiate | Signing | Sealing, and Microsoft documents that
                // default. So on the primary path this is inert, and an earlier
                // version of this comment claiming the previous code "bound in
                // the clear" was simply wrong -- EventId 108 from a live run
                // records sign-and-seal being established, with no fallback.
                //
                // What is genuinely new is the SSL fallback and the eager bind.
                // Stating the flags anyway is deliberate: the default is a
                // framework decision that could change, and this connection has
                // to be protected for the directory to accept a write at all.
                //
                // Sign-and-seal leads because it encrypts through the negotiated
                // security package and needs no certificate trust, so it asks
                // nothing new of existing deployments. SSL covers directories
                // that will not negotiate sealing.
                //
                // The PORT each mechanism targets is decided by LdapChannelPorts,
                // not taken from configuration directly, because the two are not
                // independent: 389 upgrades in band and is not listening for a TLS
                // ClientHello, while 636 is TLS from the first byte and cannot
                // answer an LDAP BindRequest. Pairing them wrongly produces
                // 0x8007203A "the server is not operational" no matter which
                // directory is on the other end -- a self-inflicted failure that
                // was read as a directory problem for several rounds.
                var sealedPort = LdapChannelPorts.SealedPortFor(_options.LdapPort);
                var sslPort = LdapChannelPorts.SslPortFor(_options.LdapPort);

                Exception? sealingFailure = null;

                if (sealedPort is null)
                {
                    // LdapPort is the LDAPS port, so a sealed bind has nowhere
                    // valid to go. Logged rather than passed over silently: without
                    // it, EventId 108 reporting "SSL" instead of "sign-and-seal"
                    // looks like sealing was tried and refused by the directory.
                    LogSealedBindSkippedForLdapsPort(Logger, host, _options.LdapPort, null);
                }
                else
                {
                    try
                    {
                        var context = CreateVerifiedContext(
                            FormattableString.Invariant($"{host}:{sealedPort.Value}"),
                            ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing);

                        LogSecureChannelEstablished(Logger, "sign-and-seal", host, sealedPort.Value, null);
                        return context;
                    }
                    catch (Exception failure)
                    {
                        sealingFailure = failure;
                        LogSealingUnavailable(Logger, host, sslPort, failure);
                    }
                }

                try
                {
                    var context = CreateVerifiedContext(
                        FormattableString.Invariant($"{host}:{sslPort}"),
                        ContextOptions.Negotiate | ContextOptions.SecureSocketLayer);

                    LogSecureChannelEstablished(Logger, "SSL", host, sslPort, null);
                    return context;
                }
                catch (Exception sslFailure)
                {
                    // Both channels reported when both ran, because "which one
                    // failed and how" is the whole diagnostic value here. When the
                    // sealed attempt was skipped there is only one real failure to
                    // report, and inventing a second would misrepresent it.
                    if (sealingFailure is null)
                    {
                        throw new InvalidOperationException(
                            FormattableString.Invariant(
                                $"Failed to create PrincipalContext over an SSL channel to {host}:{sslPort}. A signed-and-sealed bind was not attempted because LdapPort is the LDAPS port."),
                            sslFailure);
                    }

                    throw new InvalidOperationException(
                        "Failed to create PrincipalContext over either a signed-and-sealed or an SSL channel.",
                        new AggregateException(sealingFailure, sslFailure));
                }
            }
        }

        /// <inheritdoc />
        /// <remarks>
        /// Reads <c>minPwdLength</c> from the domain. Returns <see langword="null"/>
        /// when the value is absent; throws when the directory cannot be reached
        /// or read — both are turned into the logged fallback by
        /// <see cref="DomainPasswordPolicy.ResolveMinimumLength"/>. Caching and that
        /// fallback decision belong to the base class; this supplies only the
        /// AccountManagement-specific lookup.
        /// </remarks>
        protected override Task<int?> ReadMinPwdLength()
        {
            DirectoryEntry? entry = null; // Initialize to null for try-finally
            try
            {
                entry = _options.UseAutomaticContext
                    ? Domain.GetCurrentDomain().GetDirectoryEntry()
                    : GetDirectoryEntry();

                var val = entry?.Properties["minPwdLength"]?.Value is int minLength ? minLength : (int?)null;
                return Task.FromResult(val);
            }
            finally
            {
                entry?.Dispose(); // Ensure disposal in finally block
            }
        }


        /// <summary>
        /// Builds a <see cref="PrincipalContext"/> and forces it to bind.
        /// </summary>
        /// <remarks>
        /// <see cref="PrincipalContext"/> connects lazily, so a context whose
        /// channel cannot be established is returned looking healthy and fails
        /// much later, somewhere unrelated. Reading
        /// <see cref="PrincipalContext.ConnectedServer"/> forces the bind here,
        /// which is what makes "try sealing, then fall back" possible at all: the
        /// fallback needs the first attempt to have genuinely failed by now.
        /// </remarks>
        private PrincipalContext CreateVerifiedContext(string server, ContextOptions options)
        {
            // The overload that accepts ContextOptions also requires a container.
            // Null means the domain root, which is what the previous
            // container-less constructor bound to, so the search scope is
            // unchanged -- only the channel is.
            var context = new PrincipalContext(
                ContextType.Domain,
                server,
                container: null,
                options,
                _options.LdapUsername,
                _options.LdapPassword);

            try
            {
                _ = context.ConnectedServer;
                return context;
            }
            catch
            {
                context.Dispose();
                throw;
            }
        }

        /// <summary>
        /// Binds the domain naming context — the object that carries
        /// <c>minPwdLength</c> — using the configured service-account credentials.
        /// Every failure to bind or to resolve the naming context propagates so
        /// the caller can log it; this method itself never returns
        /// <see langword="null"/>.
        /// </summary>
        /// <remarks>
        /// <para>This used to pass a bare <c>host:port</c> to <see cref="DirectoryEntry"/>,
        /// which is not an ADSI path. It failed with <c>0x80005000</c>
        /// (<c>E_ADS_BAD_PATHNAME</c>) on every request, so any deployment running
        /// <c>UseAutomaticContext: false</c> silently advertised the fallback minimum
        /// length of 6 while logging the warning each time. The degradation behaved
        /// exactly as designed, which is why it went unnoticed.</para>
        /// <para>Adding the scheme alone would not have been enough.
        /// <c>minPwdLength</c> is an attribute of the domain naming context, not of
        /// the server root, so <c>LDAP://host:port</c> binds an object that does not
        /// carry it and yields <see langword="null"/> — the "value absent" case,
        /// which stops the warning and makes the failure invisible. The naming
        /// context is therefore read from the rootDSE rather than derived from the
        /// configured host name, which need not correspond to the domain's DN.</para>
        /// </remarks>
        /// <returns>A <see cref="DirectoryEntry"/> bound to the domain naming context. The
        /// return type stays nullable only to match the automatic-context branch of the
        /// caller's ternary in <see cref="ReadMinPwdLength"/> (<c>Domain.GetCurrentDomain().GetDirectoryEntry()</c>),
        /// not because this method itself can produce null.</returns>
        private DirectoryEntry? GetDirectoryEntry()
        {
            // No LdapHostnames-empty guard here: the constructor already ran
            // AppSettingsValidation.ValidateServiceAccount(opts, required:
            // !UseAutomaticContext) (see ValidateOptions, :248), which is the
            // single point enforcing that LdapHostnames is non-empty whenever
            // UseAutomaticContext is false, and this method is only ever called
            // when UseAutomaticContext is false (see ReadMinPwdLength, :1007).
            // Reaching this point implies that check ran and passed.
            var host = _options.LdapHostnames.First();

            // No local catch anywhere below: a bind or read failure propagates to
            // ResolveMinimumLength, which logs it and returns the fallback. Turning
            // a reachability failure into a null here would present it as "the
            // directory does not publish this value" and silence the warning.
            using var rootDse = new DirectoryEntry(
                AdsiPath.ForRootDse(host, _options.LdapPort),
                _options.LdapUsername,
                _options.LdapPassword);

            // Accessing Properties is what actually binds.
            var namingContext = rootDse.Properties["defaultNamingContext"]?.Value as string;

            if (string.IsNullOrWhiteSpace(namingContext))
            {
                throw new InvalidOperationException(
                    FormattableString.Invariant(
                        $"The rootDSE at '{host}:{_options.LdapPort}' returned no defaultNamingContext, so the domain naming context that carries minPwdLength cannot be located."));
            }

            return new DirectoryEntry(
                AdsiPath.ForNamingContext(host, _options.LdapPort, namingContext),
                _options.LdapUsername,
                _options.LdapPassword);
        }
    }
}
#endif
