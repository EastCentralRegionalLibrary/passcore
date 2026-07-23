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
    public class PasswordChangeProvider : PasswordChangeProviderBase, IPasswordLengthRequirement, IGroupMembershipTester
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

        public PasswordChangeProvider(
            ILogger<PasswordChangeProvider> logger,
            IOptions<PasswordChangeOptions> options,
            IOptions<ClientSettings> clientSettings,
            IEnumerable<IPasswordPolicy> policies)
            : base(logger, clientSettings?.Value, policies)
        {
            ArgumentNullException.ThrowIfNull(options);
            _options = options.Value;
            SetIdType();

            if (_options.AllowAdministrativeReset && _options.UseAutomaticContext)
                LogAdminResetIgnoredInAutomaticContext(Logger, null);
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

                if (_options.UpdateLastPassword && userPrincipal.LastPasswordSet == null) // Check if 'UpdateLastPassword' option is enabled and LastPasswordSet is null
                {
                    SetLastPassword(userPrincipal); // Update the 'pwdLastSet' attribute if conditions are met
                }

                if (!ValidateUserCredentials(userPrincipal.UserPrincipalName, context.CurrentPassword, principalContext)) // Validate provided current password
                {
                    throw new InvalidCredentialsException(DirectoryErrorTranslator.InvalidCredentialsMessage);
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
                // Never let raw AccountManagement/COM exception text reach the wire:
                // recover the Win32 code from the exception chain when present (e.g.
                // COMException 0x800708C5 for a policy rejection) and route it through
                // the shared translator; anything unrecognizable degrades to a
                // curated directory-failure message with the detail preserved for logs.
                throw DirectoryErrorTranslator.TranslateException(ex, _options.ErrorDisclosureMode);
            }

            return Task.CompletedTask;
        }

        /// <inheritdoc />
        public Task<int> GetMinimumLengthAsync()
        {
            return Task.FromResult(AcquireDomainPasswordLength());
        }

        /// <inheritdoc />
        public Task<bool> IsMemberOfGroupAsync(string username, string groupName)
        {
            // Every operation in this method is a service-account directory read
            // (context, resolve, group enumeration); a failure is infrastructure,
            // never an end-user credential signal. There is no request context
            // here, so the correlation ID is unavailable — the base class logs the
            // propagated failure with the correlation ID as a backstop.
            try
            {
                using var principalContext = RunAsServiceAccount(
                    "acquire principal context", correlationId: null, AcquirePrincipalContext);
                var userPrincipal = RunAsServiceAccount(
                    "resolve user by identity", correlationId: null,
                    () => UserPrincipal.FindByIdentity(principalContext, _idType, FixUsernameWithDomain(username)));
                if (userPrincipal == null) return Task.FromResult(false);

                try
                {
                    var groups = userPrincipal.GetGroups();
                    if (groups.Any(group => group.Name.Equals(groupName, StringComparison.OrdinalIgnoreCase)))
                        return Task.FromResult(true);
                }
                catch
                {
                    var groups = userPrincipal.GetAuthorizationGroups();
                    if (groups.Any(group => group.Name.Equals(groupName, StringComparison.OrdinalIgnoreCase)))
                        return Task.FromResult(true);
                }

                return Task.FromResult(false);
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
        /// Validates the user's current credentials against Active Directory.
        /// Attempts to validate using PrincipalContext.ValidateCredentials first, and falls back to LogonUser if necessary.
        /// </summary>
        /// <param name="upn">The User Principal Name of the user.</param>
        /// <param name="currentPassword">The current password provided by the user.</param>
        /// <param name="principalContext">The PrincipalContext to use for validation.</param>
        /// <returns>True if credentials are valid, or if the error code indicates password must be changed or is expired, otherwise false.</returns>
        private bool ValidateUserCredentials(
            string upn,
            string currentPassword,
            PrincipalContext principalContext)
        {
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
            var errorCode = System.Runtime.InteropServices.Marshal.GetLastWin32Error(); // Get the last Win32 error code

            // Expired / must-change-at-next-logon still proves the user knows the current
            // password; the shared classification keeps this decision identical to the
            // LDAP provider's bind handling.
            return DirectoryErrorTranslator.IsPasswordExpiredOrMustChange(errorCode);
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
        /// Sets the 'pwdLastSet' attribute to -1 to force password change at next logon.
        /// This is used when the 'UpdateLastPassword' option is enabled and the LastPasswordSet is null.
        /// </summary>
        /// <param name="userPrincipal">The UserPrincipal object for which to set the 'pwdLastSet' attribute.</param>
        private void SetLastPassword(Principal userPrincipal)
        {
            var directoryEntry = (DirectoryEntry)userPrincipal.GetUnderlyingObject(); // Get the underlying DirectoryEntry object
            var pwdLastSetProperty = directoryEntry.Properties["pwdLastSet"]; // Get the 'pwdLastSet' property

            if (pwdLastSetProperty == null) // Check if 'pwdLastSet' property exists
            {
                throw new PasswordPolicyViolationException("The 'pwdLastSet' property is missing on the user principal.", ApiErrorCode.Generic);
            }

            try
            {
                pwdLastSetProperty.Value = -1; // Set 'pwdLastSet' to -1 to force password change at next logon
                directoryEntry.CommitChanges(); // Commit changes to Active Directory
            }
            catch (Exception) // Catch exceptions during attribute update
            {
                throw new PasswordPolicyViolationException("Failed to update 'pwdLastSet' attribute.", ApiErrorCode.ChangeNotPermitted);
            }
        }

        /// <summary>
        /// Updates the user's password in Active Directory with a user-context
        /// ChangePassword. On failure, an administrative SetPassword fallback
        /// may fire — but only when <see cref="PasswordChangeOptions.AllowAdministrativeReset"/>
        /// is enabled (default off), the user's current password was verified in
        /// this request, the failure is one a reset can cure (new-password
        /// policy or cannot-change; the shared <see cref="AdministrativeReset"/>
        /// gate), and the provider is bound with service-account credentials
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

                var domain = $"{_options.LdapHostnames.First()}:{_options.LdapPort}"; // Construct domain string from hostname and port
                try
                {
                    return new PrincipalContext( // Create PrincipalContext with LDAP credentials
                        ContextType.Domain,
                        domain,
                        _options.LdapUsername,
                        _options.LdapPassword);
                }
                catch (Exception ex)
                {
                    throw new InvalidOperationException("Failed to create PrincipalContext.", ex); // Re-throw exception to signal failure
                }
            }
        }

        /// <summary>
        /// Retrieves the minimum password length policy from Active Directory.
        /// Uses either automatic domain context or specified LDAP connection details based on 'UseAutomaticContext' option.
        /// Returns a default value of 6 if retrieval fails.
        /// </summary>
        /// <returns>The minimum password length as an integer.</returns>
        private int AcquireDomainPasswordLength()
        {
            DirectoryEntry? entry = null; // Initialize to null for try-finally and error handling
            try
            {
                entry = _options.UseAutomaticContext
                    ? Domain.GetCurrentDomain().GetDirectoryEntry()
                    : GetDirectoryEntry();

                if (entry?.Properties["minPwdLength"]?.Value is int minLength) // Null-conditional checks and type check
                {
                    return minLength;
                }
                else
                {
                    return 6; // Default minimum password length
                }
            }
            catch (Exception)
            {
                return 6; // Default minimum password length in case of exception
            }
            finally
            {
                entry?.Dispose(); // Ensure disposal in finally block
            }
        }


        /// <summary>
        /// Creates and returns a DirectoryEntry object using LDAP connection details from options.
        /// This method is extracted for better readability and reusability.
        /// Returns null and logs a warning if LDAP Hostnames are not configured.
        /// </summary>
        /// <returns>A <see cref="DirectoryEntry"/> object configured with LDAP credentials, or null if configuration is missing.</returns>
        private DirectoryEntry? GetDirectoryEntry()
        {
            if (!_options.LdapHostnames.Any()) // Check if LdapHostnames is empty
            {
                return null; // Return null to indicate failure to create DirectoryEntry
            }

            var domain = $"{_options.LdapHostnames.First()}:{_options.LdapPort}"; // Construct domain string
            try
            {
                return new DirectoryEntry( // Create DirectoryEntry with LDAP credentials
                    domain,
                    _options.LdapUsername,
                    _options.LdapPassword);
            }
            catch (Exception)
            {
                return null; // Return null if DirectoryEntry creation fails
            }
        }
    }
}
#endif
