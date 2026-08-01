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
    public class PasswordChangeProvider : PasswordChangeProviderBase, IPasswordLengthRequirement, IGroupMembershipTester, IGroupMembershipResolver
    {
        /// <inheritdoc />
        public override ErrorDisclosureMode ErrorDisclosureMode => _options.ErrorDisclosureMode;

        private readonly PasswordChangeOptions _options;

        // The provider is registered as a singleton, so this is shared across
        // requests -- which is the point: the value it holds is domain-wide.
        private readonly CachedDomainMinimumLength _minimumLength = new();
        private IdentityType _idType = IdentityType.UserPrincipalName;

        private static readonly Action<ILogger, Exception?> LogAdminResetIgnoredInAutomaticContext =
            LoggerMessage.Define(
                LogLevel.Warning,
                new EventId(103, nameof(LogAdminResetIgnoredInAutomaticContext)),
                "AllowAdministrativeReset is enabled but UseAutomaticContext is true, so it is " +
                "ignored: in automatic-context mode there is no service account to perform an " +
                "administrative reset with. Configure explicit LdapUsername/LdapPassword bind " +
                "credentials (UseAutomaticContext=false) if the fallback is wanted.");

        // Warning, not error, and deliberately so. Everything else on this path
        // works and is covered end-to-end against a live directory: reads, binds,
        // credential verification, group membership, minPwdLength, policy
        // evaluation and error routing. Refusing to start would break deployments
        // using all of that, and would claim more than the evidence supports.
        //
        // What is NOT claimed here is a cause. The change fails with 0x80070547
        // and the reason is unidentified; reachability, certificate trust,
        // channel protection, Kerberos realm mapping and port selection have each
        // been tested and ruled out. The message says what is affected and what to
        // do, not why.
        private static readonly Action<ILogger, Exception?> LogExplicitBindPasswordChangeUnverified =
            LoggerMessage.Define(
                LogLevel.Warning,
                new EventId(115, nameof(LogExplicitBindPasswordChangeUnverified)),
                "UseAutomaticContext is false, so password changes are performed over an " +
                "explicitly-bound context. THE PASSWORD CHANGE ITSELF IS NOT VERIFIED TO WORK ON " +
                "THIS PATH: against a live directory it fails with 0x80070547 " +
                "(ERROR_CANT_ACCESS_DOMAIN_INFO), and the user receives a generic " +
                "\"the directory service could not complete the password change request\" error. " +
                "Everything else on this path is verified and unaffected - reads, credential " +
                "verification, group membership and policy evaluation all work. If password " +
                "changes fail this way, run PassCore on a domain-joined host with " +
                "UseAutomaticContext=true, which acquires its context by a different path. " +
                "See TESTING.md, \"The AD password change on the explicit-bind path\".");

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
                "This is the channel for directory reads and writes made through this context. " +
                "IADsUser::ChangePassword selects its own transport and is not governed by it.");

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

        public PasswordChangeProvider(
            ILogger<PasswordChangeProvider> logger,
            IOptions<PasswordChangeOptions> options,
            IOptions<ClientSettings> clientSettings,
            IEnumerable<IPasswordPolicy> policies)
            : base(logger, clientSettings?.Value, policies)
        {
            ArgumentNullException.ThrowIfNull(options);
            _options = options.Value;
            ValidateOptions(_options);
            SetIdType();

            if (_options.AllowAdministrativeReset && _options.UseAutomaticContext)
                LogAdminResetIgnoredInAutomaticContext(Logger, null);

            // Told to the operator at startup rather than to the user at failure.
            // Without this the first sign is an end user receiving a generic
            // directory error, which reads as a transient outage rather than a
            // configuration that may never have been able to change a password.
            if (!_options.UseAutomaticContext)
                LogExplicitBindPasswordChangeUnverified(Logger, null);
        }

        private static void ValidateOptions(PasswordChangeOptions opts)
        {
            if (opts == null)
                throw new ArgumentNullException(nameof(opts));

            if (!opts.UseAutomaticContext)
            {
                if (opts.LdapHostnames == null || opts.LdapHostnames.Length == 0)
                    throw new ArgumentException("LDAP Hostnames are not configured.");

                if (string.IsNullOrWhiteSpace(opts.LdapUsername))
                    throw new ArgumentException("LDAP Username is not configured.");

                if (string.IsNullOrWhiteSpace(opts.LdapPassword))
                    throw new ArgumentException("LDAP Password is not configured.");
            }
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
        protected override Task ChangePasswordCore(PasswordChangeContext context, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(context);

            try
            {
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
                    HandleCannotChangePassword(context, userPrincipal, currentPasswordVerified: true);
                }
                else
                {
                    UpdatePassword(context, userPrincipal, currentPasswordVerified: true);
                }

                userPrincipal.Save();
            }
            catch (PasswordChangeException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // Terminal backstop. Every failure that carries a meaningful
                // directory code is already handled at its stage — service-account
                // operations via RunAsServiceAccount, the modify itself via
                // UpdatePassword's catch, the cannot-change flag pre-flight. An
                // exception reaching HERE is an unexpected, non-directory-typed
                // fault (e.g. a Save() failure) with no reliable Win32 code, so
                // it is classified as infrastructure directly rather than by
                // speculatively re-scanning the chain. This matches the LDAP
                // provider's terminal catch (see the routing-matrix doc, "Terminal
                // catch"). Raw exception text stays in the inner exception (logs),
                // never on the wire.
                throw new DirectoryUnavailableException(
                    DirectoryErrorTranslator.DirectoryFailureMessage, ex);
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task<int> GetMinimumLengthAsync()
        {
            return Task.FromResult(AcquireDomainPasswordLength());
        }

        /// <summary>
        /// Reports whether <paramref name="username"/> is a member of
        /// <paramref name="groupName"/>, directly, by primary group, or transitively.
        /// </summary>
        /// <remarks>
        /// <para><b>A negative answer means "determined not to be a member", never
        /// "could not tell".</b> A positive match is definitive the moment it is found,
        /// so each enumeration returns immediately on a hit and no later failure can
        /// affect it. A negative answer is only trustworthy if every enumeration that
        /// could still have produced a match completed, so a failed enumeration is
        /// recorded and the method throws the shared infrastructure failure instead of
        /// returning <see langword="false"/>.</para>
        /// <para><b>Only security groups can match.</b> <c>GetAuthorizationGroups</c>
        /// is the sole source, and it returns the complete transitive security-group
        /// closure including the primary group. Distribution groups are therefore never
        /// matched, by either list, and that is deliberate: a distribution group cannot
        /// enter a Windows access token, so it carries no authorization anywhere else
        /// in Windows, and on many directories users can add themselves to one. A
        /// self-joinable group must not be able to satisfy <c>AllowedAdGroups</c>, and
        /// an administrator converting a group to a distribution group must not be able
        /// to quietly step out of <c>RestrictedAdGroups</c> — see the LDAP provider,
        /// which warns on exactly that condition.</para>
        /// <para>Reporting "not a member" for a membership that could not be determined
        /// makes <c>RestrictedAdGroups</c> <em>fail open</em>, letting a member of
        /// <c>Domain Admins</c> through during a partial directory failure. This keeps
        /// it failing closed, matching the LDAP provider for the same condition.</para>
        /// </remarks>
        public async Task<bool> IsMemberOfGroupAsync(string username, string groupName)
        {
            var membership = await ResolveMembershipAsync(username).ConfigureAwait(false);
            return await membership.IsMemberOfAnyAsync(new[] { groupName }).ConfigureAwait(false);
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
        public Task<IResolvedGroupMembership> ResolveMembershipAsync(string username)
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

                if (userPrincipal == null)
                    return Task.FromResult<IResolvedGroupMembership>(AdResolvedMembership.NoSuchUser);

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

                return Task.FromResult<IResolvedGroupMembership>(
                    new AdResolvedMembership(groupNames, undetermined, _options.ErrorDisclosureMode));
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
        /// A single resolution of one user's group names, queried in memory.
        /// </summary>
        private sealed class AdResolvedMembership : IResolvedGroupMembership
        {
            /// <summary>An unresolvable user belongs to nothing, matching the previous <c>false</c> for a null principal.</summary>
            internal static readonly AdResolvedMembership NoSuchUser =
                new(new HashSet<string>(StringComparer.OrdinalIgnoreCase), null, ErrorDisclosureMode.Hardened);

            private readonly HashSet<string> _groupNames;
            private readonly Exception? _undetermined;
            private readonly ErrorDisclosureMode _disclosureMode;

            internal AdResolvedMembership(
                HashSet<string> groupNames, Exception? undetermined, ErrorDisclosureMode disclosureMode)
            {
                _groupNames = groupNames;
                _undetermined = undetermined;
                _disclosureMode = disclosureMode;
            }

            public Task<bool> IsMemberOfAnyAsync(IReadOnlyCollection<string> groupNames)
            {
                if (groupNames is null || groupNames.Count == 0)
                    return Task.FromResult(false);

                // A match is definitive regardless of what else failed.
                if (groupNames.Any(_groupNames.Contains))
                    return Task.FromResult(true);

                // Nothing matched. That is only an answer if both enumerations ran.
                if (_undetermined is not null)
                {
                    throw DirectoryErrorTranslator.TranslateException(
                        _undetermined, _disclosureMode, DirectoryActor.ServiceAccount);
                }

                return Task.FromResult(false);
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
        private string FixUsernameWithDomain(string username)
        {
            if (_idType != IdentityType.UserPrincipalName) return username; // No fixing needed if IdentityType is not UserPrincipalName

            var parts = username.Split('@', StringSplitOptions.RemoveEmptyEntries); // Split username by '@' to check for domain part

            // Append domain to username if no domain part is present and default domain is configured
            return parts.Length > 1 || string.IsNullOrWhiteSpace(_options.DefaultDomain) ? username : $"{username}@{_options.DefaultDomain}";
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
        private void UpdatePassword(
            PasswordChangeContext context,
            AuthenticablePrincipal userPrincipal,
            bool currentPasswordVerified)
        {
            try
            {
                userPrincipal.ChangePassword(context.CurrentPassword, context.NewPassword);
            }
            catch (Exception ex)
            {
                var translated = DirectoryErrorTranslator.TranslateException(
                    ex, _options.ErrorDisclosureMode, out var failureClass);

                // Automatic-context mode never resets administratively (there is
                // no service account to reset with); otherwise the shared
                // class-based gate decides — only ChangeNotPermitted is ever
                // rescuable. Ineligible failures surface translated.
                var attemptReset = !_options.UseAutomaticContext
                    && AdministrativeReset.ShouldAttempt(
                        _options.AllowAdministrativeReset,
                        currentPasswordVerified,
                        failureClass);

                if (!attemptReset)
                    throw translated;

                PerformAdministrativeReset(context, userPrincipal, translated);
            }
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
        private void HandleCannotChangePassword(
            PasswordChangeContext context,
            AuthenticablePrincipal userPrincipal,
            bool currentPasswordVerified)
        {
            var blocked = DirectoryErrorTranslator.CreateChangeNotPermittedError();

            var attemptReset = !_options.UseAutomaticContext
                && AdministrativeReset.ShouldAttempt(
                    _options.AllowAdministrativeReset,
                    currentPasswordVerified,
                    DirectoryFailureClass.ChangeNotPermitted);

            if (!attemptReset)
                throw blocked;

            PerformAdministrativeReset(context, userPrincipal, blocked);
        }

        /// <summary>
        /// The single reset execution path: administrative SetPassword with the
        /// service-account-bound principal context, followed by the shared loud
        /// Warning log. Reached only through the
        /// <see cref="AdministrativeReset"/> gate.
        /// </summary>
        /// <param name="context">The password change context.</param>
        /// <param name="userPrincipal">The UserPrincipal object for the user.</param>
        /// <param name="originalFailure">The translated failure or blocking condition that triggered the reset.</param>
        private void PerformAdministrativeReset(
            PasswordChangeContext context,
            AuthenticablePrincipal userPrincipal,
            Exception originalFailure)
        {
            userPrincipal.SetPassword(context.NewPassword);
            AdministrativeReset.LogPerformed(Logger, context.CorrelationId, context.Username, originalFailure);
        }

        /// <summary>
        /// Sets the identity type based on configuration options, providing fault tolerance for various string inputs.
        /// Uses a switch expression to map string configuration values to <see cref="IdentityType"/> enum values.
        /// Defaults to <see cref="IdentityType.UserPrincipalName"/> if no match or invalid input.
        /// </summary>
        private void SetIdType()
        {
            _idType = _options.IdTypeForUser?.Trim().ToLowerInvariant() switch // Use switch expression for concise mapping
            {
                "distinguishedname" or "distinguished name" or "dn" => IdentityType.DistinguishedName,
                "globally unique identifier" or "globallyuniqueidentifier" or "guid" => IdentityType.Guid,
                "name" or "nm" => IdentityType.Name,
                "samaccountname" or "accountname" or "sam account" or "sam account name" or "sam" => IdentityType.SamAccountName,
                "securityidentifier" or "securityid" or "secid" or "security identifier" or "sid" => IdentityType.Sid,
                _ => IdentityType.UserPrincipalName // Default to UserPrincipalName if no match or invalid input
            };
        }

        /// <summary>
        /// Runs a service-account directory operation, guaranteeing that any
        /// failure surfaces as an infrastructure error rather than an end-user
        /// credential/existence/account-state error. This is the AD provider's
        /// counterpart to the LDAP provider's <c>BindAsServiceAccount</c>: both
        /// route through the shared <see cref="DirectoryErrorTranslator"/> with
        /// <see cref="DirectoryActor.ServiceAccount"/>, which is the single point
        /// enforcing "a service-account failure can never be reported as invalid
        /// credentials." Every service-account operation in this provider goes
        /// through this method, so a future maintainer adding one inherits the
        /// guarantee. Domain exceptions (should any arise) pass through unchanged.
        /// </summary>
        /// <typeparam name="T">The operation's result type.</typeparam>
        /// <param name="operation">A short label used for diagnostics logging.</param>
        /// <param name="correlationId">The request correlation ID, or null when unavailable.</param>
        /// <param name="action">The service-account operation to run.</param>
        /// <returns>The operation's result.</returns>
        private T RunAsServiceAccount<T>(string operation, string? correlationId, Func<T> action)
        {
            try
            {
                return action();
            }
            catch (PasswordChangeException)
            {
                throw;
            }
            catch (Exception ex)
            {
                ServiceAccountFailure.Log(Logger, correlationId, operation, ServiceAccountHost(), ex);
                throw DirectoryErrorTranslator.TranslateException(
                    ex, _options.ErrorDisclosureMode, DirectoryActor.ServiceAccount);
            }
        }

        /// <summary>
        /// Describes the directory host used for service-account operations,
        /// for diagnostics logging only.
        /// </summary>
        private string ServiceAccountHost() =>
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
                if (!_options.LdapHostnames.Any()) // Check if LdapHostnames is empty when not using automatic context
                {
                    throw new InvalidOperationException("LDAP Hostnames are not configured."); // Throw exception to signal configuration error
                }

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
                try
                {
                    var context = CreateVerifiedContext(
                        FormattableString.Invariant($"{host}:{_options.LdapPort}"),
                        ContextOptions.Negotiate | ContextOptions.Signing | ContextOptions.Sealing);

                    LogSecureChannelEstablished(Logger, "sign-and-seal", host, _options.LdapPort, null);
                    return context;
                }
                catch (Exception sealingFailure)
                {
                    // LDAPS runs on its own port. When the configured port is the
                    // plaintext default the operator has not chosen one, so the
                    // well-known 636 is used; any other value is taken as
                    // deliberate and left alone.
                    var sslPort = _options.LdapPort == PlaintextLdapPort ? SecureLdapPort : _options.LdapPort;

                    LogSealingUnavailable(Logger, host, sslPort, sealingFailure);

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
                        // Both channels reported, because "which one failed and
                        // how" is the whole diagnostic value here.
                        throw new InvalidOperationException(
                            "Failed to create PrincipalContext over either a signed-and-sealed or an SSL channel.",
                            new AggregateException(sealingFailure, sslFailure));
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves the minimum password length policy from Active Directory,
        /// falling back — visibly, via a logged Warning — to
        /// <see cref="DomainPasswordPolicy.DefaultMinimumLength"/> when the domain
        /// policy cannot be read. The fallback/log decision lives in the shared,
        /// testable <see cref="DomainPasswordPolicy.ResolveMinimumLength"/>; this
        /// method supplies only the AccountManagement-specific lookup.
        /// </summary>
        /// <returns>The minimum password length as an integer.</returns>
        // Cached with a short time-to-live: this runs on every POST, before the
        // caller has proved anything, and the value is domain-wide. Only a
        // directory-sourced value is cached, so a failing lookup keeps
        // re-attempting and keeps logging its warning.
        private int AcquireDomainPasswordLength() =>
            _minimumLength.Resolve(Logger, ReadMinPwdLength);

        /// <summary>
        /// Reads <c>minPwdLength</c> from the domain. Returns <see langword="null"/>
        /// when the value is absent; throws when the directory cannot be reached
        /// or read — both are turned into the logged fallback by
        /// <see cref="DomainPasswordPolicy.ResolveMinimumLength"/>.
        /// </summary>
        private int? ReadMinPwdLength()
        {
            DirectoryEntry? entry = null; // Initialize to null for try-finally
            try
            {
                entry = _options.UseAutomaticContext
                    ? Domain.GetCurrentDomain().GetDirectoryEntry()
                    : GetDirectoryEntry();

                return entry?.Properties["minPwdLength"]?.Value is int minLength ? minLength : null;
            }
            finally
            {
                entry?.Dispose(); // Ensure disposal in finally block
            }
        }


        /// <summary>The standard plaintext LDAP port; the default for <c>LdapPort</c>.</summary>
        private const int PlaintextLdapPort = 389;

        /// <summary>The standard LDAPS port, used when falling back to SSL from an unset <c>LdapPort</c>.</summary>
        private const int SecureLdapPort = 636;

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
        /// Returns <see langword="null"/> only when no LDAP hostnames are configured;
        /// every other failure propagates so the caller can log it.
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
        /// <returns>A <see cref="DirectoryEntry"/> bound to the domain naming context, or null if no hostnames are configured.</returns>
        private DirectoryEntry? GetDirectoryEntry()
        {
            if (!_options.LdapHostnames.Any()) // Check if LdapHostnames is empty
            {
                return null; // Return null to indicate failure to create DirectoryEntry
            }

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
