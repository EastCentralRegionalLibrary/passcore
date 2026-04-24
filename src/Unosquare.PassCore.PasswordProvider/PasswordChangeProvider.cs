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
        // Readonly fields
        private readonly PasswordChangeOptions _options;
        private IdentityType _idType = IdentityType.UserPrincipalName; // Default identity type

        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordChangeProvider"/> class.
        /// Constructor to inject logger and options.
        /// </summary>
        /// <param name="logger">The logger interface for logging events within this provider.</param>
        /// <param name="options">The options configuration for password change operations, injected through IOptions.</param>
        /// <param name="policies">The password policies.</param>
        public PasswordChangeProvider(
            ILogger<PasswordChangeProvider> logger,
            IOptions<PasswordChangeOptions> options,
            IEnumerable<IPasswordPolicy> policies)
            : base(logger, policies)
        {
            ArgumentNullException.ThrowIfNull(logger);
            ArgumentNullException.ThrowIfNull(options);
            _options = options.Value;
            SetIdType(); // Determine IdentityType from options
        }

        /// <inheritdoc />
        protected override async Task ChangePasswordCore(PasswordChangeContext context, CancellationToken cancellationToken)
        {
            ArgumentNullException.ThrowIfNull(context);

            var fixedUsername = FixUsernameWithDomain(context.Username);

            using var principalContext = AcquirePrincipalContext(); // Acquire PrincipalContext for AD operations, using 'using' for automatic disposal
            var userPrincipal = UserPrincipal.FindByIdentity(principalContext, _idType, fixedUsername); // Find the UserPrincipal object

            if (userPrincipal == null) // Check if UserPrincipal is null
            {
                throw new UserNotFoundException();
            }

            if (userPrincipal.UserCannotChangePassword) // Check if the UserCannotChangePassword flag is set
            {
                throw new PasswordPolicyViolationException("User cannot change password", ApiErrorCode.ChangeNotPermitted);
            }

            if (_options.UpdateLastPassword && userPrincipal.LastPasswordSet == null) // Check if 'UpdateLastPassword' option is enabled and LastPasswordSet is null
            {
                SetLastPassword(userPrincipal); // Update the 'pwdLastSet' attribute if conditions are met
            }

            if (!ValidateUserCredentials(userPrincipal.UserPrincipalName, context.CurrentPassword, principalContext)) // Validate provided current password
            {
                throw new InvalidCredentialsException();
            }

            UpdatePassword(context.CurrentPassword, context.NewPassword, userPrincipal); // Attempt to update the password

            userPrincipal.Save(); // Save changes to Active Directory
        }

        /// <inheritdoc />
        public Task<int> GetMinimumLengthAsync()
        {
            return Task.FromResult(AcquireDomainPasswordLength());
        }

        /// <inheritdoc />
        public Task<bool> IsMemberOfGroupAsync(string username, string groupName)
        {
            using var principalContext = AcquirePrincipalContext();
            var userPrincipal = UserPrincipal.FindByIdentity(principalContext, _idType, FixUsernameWithDomain(username));
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

            // Return true if error code indicates password must change or is expired (treat these as valid for password change process)
            return errorCode is NativeMethods.ErrorPasswordMustChange or NativeMethods.ErrorPasswordExpired;
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
        /// Updates the user's password in Active Directory.
        /// Attempts to use ChangePassword first, and falls back to SetPassword if ChangePassword fails and 'UseAutomaticContext' is disabled.
        /// </summary>
        /// <param name="currentPassword">The user's current password.</param>
        /// <param name="newPassword">The new password to set.</param>
        /// <param name="userPrincipal">The UserPrincipal object for the user.</param>
        private void UpdatePassword(
            string currentPassword,
            string newPassword,
            AuthenticablePrincipal userPrincipal)
        {
            try
            {
                userPrincipal.ChangePassword(currentPassword, newPassword); // Attempt to change password using ChangePassword method (preferred method)
            }
            catch (Exception) // Catch exceptions during ChangePassword operation
            {
                if (_options.UseAutomaticContext) // If AutomaticContext is enabled, ChangePassword failure is critical
                {
                    throw; // Re-throw the original exception - Password update is aborted in AutomaticContext mode if ChangePassword fails
                }

                try // Attempt to use SetPassword as a fallback if ChangePassword fails and AutomaticContext is disabled
                {
                    userPrincipal.SetPassword(newPassword); // Fallback to SetPassword method if ChangePassword fails
                }
                catch (Exception) // Catch exceptions during SetPassword operation
                {
                    throw; // Re-throw the SetPassword exception as password update ultimately failed
                }
            }
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
