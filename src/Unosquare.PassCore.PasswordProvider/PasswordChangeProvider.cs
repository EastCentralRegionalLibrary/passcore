#if WINDOWS
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using Unosquare.PassCore.Common;

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
    public class PasswordChangeProvider : IPasswordChangeProvider
    {
        // Readonly fields
        private readonly PasswordChangeOptions _options;
        private readonly ILogger<PasswordChangeProvider> _logger;
        private IdentityType _idType = IdentityType.UserPrincipalName; // Default identity type

        // LoggerMessage delegates for performance optimization
        private static readonly Action<ILogger, string, Exception?> LogPerformingPasswordChange =
            LoggerMessage.Define<string>(
                LogLevel.Information,
                new EventId(100, "PerformingPasswordChange"),
                "Performing password change for user '{Username}'.");

        private static readonly Action<ILogger, string, Exception?> LogInvalidCurrentPassword =
            LoggerMessage.Define<string>(
                LogLevel.Warning,
                new EventId(101, "InvalidCurrentPassword"),
                "Invalid current password provided for user '{Username}'.");

        private static readonly Action<ILogger, string, Exception?> LogPasswordSuccessfullyUpdated =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(102, "PasswordSuccessfullyUpdated"),
                "Password successfully updated for user '{Username}'.");

        private static readonly Action<ILogger, string, string, Exception?> LogPasswordChangeComplexityError =
            LoggerMessage.Define<string, string>(
                LogLevel.Warning,
                new EventId(103, "PasswordComplexityError"),
                "Password change failed due to complexity policies: {ErrorMessage}. {ErrorDetails}");

        private static readonly Action<ILogger, string, string, Exception?> LogPasswordChangeApiError =
            LoggerMessage.Define<string, string>(
                LogLevel.Warning,
                new EventId(104, "PasswordChangeApiError"),
                "Password change failed due to API error: {ErrorMessage}. {ErrorDetails}");

        private static readonly Action<ILogger, string, string, Exception?> LogPasswordChangeUnexpectedError =
            LoggerMessage.Define<string, string>(
                LogLevel.Error,
                new EventId(105, "PasswordChangeUnexpectedError"),
                "Password change failed due to an unexpected error: {ErrorMessage}. {ErrorDetails}");

        private static readonly Action<ILogger, string, Exception?> LogUserPrincipalNotFound =
            LoggerMessage.Define<string>(
                LogLevel.Warning,
                new EventId(106, "UserPrincipalNotFound"),
                "User principal '{Username}' not found.");

        private static readonly Action<ILogger, Exception?> LogPasswordLengthTooShort =
            LoggerMessage.Define(
                LogLevel.Error,
                new EventId(107, "PasswordLengthTooShort"),
                "New password length is shorter than the Active Directory minimum password length.");

        private static readonly Action<ILogger, Exception?> LogPwnedPasswordUsed =
            LoggerMessage.Define(
                LogLevel.Error,
                new EventId(108, "PwnedPasswordUsed"),
                "New password is a known compromised password and is not allowed.");

        private static readonly Action<ILogger, Exception?> LogPasswordChangeNotPermittedFlag =
            LoggerMessage.Define(
                LogLevel.Warning,
                new EventId(109, "PasswordChangeNotPermittedFlag"),
                "User is not permitted to change their password.");

        private static readonly Action<ILogger, int, Exception?> LogValidateCredentialsWin32Error =
            LoggerMessage.Define<int>(
                LogLevel.Debug,
                new EventId(110, "ValidateCredentialsWin32Error"),
                "ValidateUserCredentials GetLastWin32Error {ErrorCode}");

        private static readonly Action<ILogger, Exception?> LogPwdLastSetMissing =
            LoggerMessage.Define(
                LogLevel.Warning,
                new EventId(111, "PwdLastSetMissing"),
                "The 'pwdLastSet' property is missing on the user principal.");

        private static readonly Action<ILogger, Exception?> LogPwdLastSetUpdated =
            LoggerMessage.Define(
                LogLevel.Information,
                new EventId(112, "PwdLastSetUpdated"),
                "The 'pwdLastSet' attribute was successfully updated.");

        private static readonly Action<ILogger, string, Exception?> LogPwdLastSetUpdateFailed =
            LoggerMessage.Define<string>(
                LogLevel.Error,
                new EventId(113, "PwdLastSetUpdateFailed"),
                "Failed to update 'pwdLastSet' attribute: {ErrorMessage}");

        private static readonly Action<ILogger, string, Exception?> LogChangePasswordAutomaticContextFailed =
            LoggerMessage.Define<string>(
                LogLevel.Warning,
                new EventId(114, "ChangePasswordAutomaticContextFailed"),
                "ChangePassword failed with AutomaticContext enabled. Password update aborted. {ErrorDetails}");

        private static readonly Action<ILogger, Exception?> LogPasswordUpdatedSetPasswordFallback =
            LoggerMessage.Define(
                LogLevel.Debug,
                new EventId(115, "PasswordUpdatedSetPasswordFallback"),
                "Password updated using SetPassword method after ChangePassword failure.");

        private static readonly Action<ILogger, string, Exception?> LogSetPasswordFailed =
            LoggerMessage.Define<string>(
                LogLevel.Error,
                new EventId(116, "SetPasswordFailed"),
                "SetPassword failed after ChangePassword failure. Password update failed. {ErrorDetails}");

        private static readonly Action<ILogger, IdentityType, Exception?> LogIdentityTypeSet =
            LoggerMessage.Define<IdentityType>(
                LogLevel.Debug,
                new EventId(117, "IdentityTypeSet"),
                "Identity type set to '{IdentityType}'.");

        private static readonly Action<ILogger, Exception?> LogAutomaticDomainContext =
            LoggerMessage.Define(
                LogLevel.Debug,
                new EventId(118, "AutomaticDomainContext"),
                "Using automatic domain context.");

        private static readonly Action<ILogger, string, Exception?> LogDomainContext =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(119, "DomainContext"),
                "Using domain context: '{Domain}'.");

        private static readonly Action<ILogger, string, Exception?> LogCreatingDirectoryEntry =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(120, "CreatingDirectoryEntry"),
                "Creating DirectoryEntry for domain: '{Domain}'.");

        private static readonly Action<ILogger, string, Exception?> LogErrorRetrievingGroups =
            LoggerMessage.Define<string>(
                LogLevel.Error,
                new EventId(887, "GroupRetrievalError"),
                "Error retrieving user groups using GetGroups. Falling back to GetAuthorizationGroups. {ErrorMessage}");

        private static readonly Action<ILogger, string, Exception?> LogErrorGroupValidation =
            LoggerMessage.Define<string>(
                LogLevel.Error,
                new EventId(888, "GroupValidationError"),
                "Error during group membership validation: {ErrorMessage}");

        // Add new LoggerMessage delegates for AcquireDomainPasswordLength
        private static readonly Action<ILogger, Exception?> LogPasswordLengthRetrievalError =
            LoggerMessage.Define(
                LogLevel.Error,
                new EventId(121, "PasswordLengthRetrievalError"),
                "Error retrieving domain password length policy from Active Directory. Defaulting to 6.");

        private static readonly Action<ILogger, Exception?> LogPasswordLengthRetrievalWarning =
            LoggerMessage.Define(
                LogLevel.Warning,
                new EventId(122, "PasswordLengthRetrievalWarning"),
                "Could not retrieve 'minPwdLength' from Active Directory or property value was not an integer. Defaulting to 6.");

        // Add new LoggerMessage delegates for AcquirePrincipalContext
        private static readonly Action<ILogger, Exception?> LogPrincipalContextCreationFailedError =
            LoggerMessage.Define(
                LogLevel.Error,
                new EventId(123, "PrincipalContextCreationFailedError"),
                "Error creating PrincipalContext with provided LDAP settings.");

        private static readonly Action<ILogger, Exception?> LogLdapHostnamesNotConfiguredWarning =
            LoggerMessage.Define(
                LogLevel.Warning,
                new EventId(124, "LdapHostnamesNotConfiguredWarning"),
                "LDAP Hostnames are not configured when UseAutomaticContext is false. PrincipalContext cannot be created.");

        // Add new LoggerMessage delegates for GetDirectoryEntry
        private static readonly Action<ILogger, Exception?> LogLdapHostnamesEmptyWarning =
            LoggerMessage.Define(
                LogLevel.Warning,
                new EventId(125, "LdapHostnamesEmptyWarning"),
                "LDAP Hostnames are not configured. Cannot create DirectoryEntry.");

        private static readonly Action<ILogger, Exception?> LogDirectoryEntryCreationFailedError =
            LoggerMessage.Define(
                LogLevel.Error,
                new EventId(126, "DirectoryEntryCreationFailedError"),
                "Error creating DirectoryEntry with provided LDAP settings.");


        /// <summary>
        /// Initializes a new instance of the <see cref="PasswordChangeProvider"/> class.
        /// Constructor to inject logger and options.
        /// </summary>
        /// <param name="logger">The logger interface for logging events within this provider.</param>
        /// <param name="options">The options configuration for password change operations, injected through IOptions.</param>
        public PasswordChangeProvider(
            ILogger<PasswordChangeProvider> logger,
            IOptions<PasswordChangeOptions> options)
        {
            _logger = logger;
            _options = options.Value;
            SetIdType(); // Determine IdentityType from options
        }

        /// <inheritdoc />
        /// <summary>
        /// Executes the password change operation for a given user.
        /// This is the main entry point for changing a user's password. It performs several validations
        /// before attempting to update the password in Active Directory.
        /// </summary>
        /// <param name="username">The username of the account to change the password for.</param>
        /// <param name="currentPassword">The user's current password, required for password change validation.</param>
        /// <param name="newPassword">The new password to set for the user.</param>
        /// <returns>An <see cref="ApiErrorItem"/> if the password change fails, otherwise null for success.</returns>
        public ApiErrorItem? PerformPasswordChange(string username, string currentPassword, string newPassword)
        {
            ApiErrorItem? errorItem = null; // Initialize error item to null (success case)

            try
            {
                var fixedUsername = FixUsernameWithDomain(username); // Ensure username is correctly formatted with domain if needed
                LogPerformingPasswordChange(_logger, fixedUsername, null);

                using var principalContext = AcquirePrincipalContext(); // Acquire PrincipalContext for AD operations, using 'using' for automatic disposal
                var userPrincipal = UserPrincipal.FindByIdentity(principalContext, _idType, fixedUsername); // Find the UserPrincipal object

                errorItem = ValidateUserPrincipal(userPrincipal, fixedUsername); // Validate if user principal is found
                if (errorItem != null) return errorItem; // Return immediately if validation fails

                errorItem = ValidateNewPasswordComplexity(newPassword); // Validate new password against complexity rules
                if (errorItem != null) return errorItem; // Return immediately if validation fails

                errorItem = ValidatePwnedPassword(newPassword); // Check if the new password is in a list of pwned passwords
                if (errorItem != null) return errorItem; // Return immediately if validation fails

                errorItem = ValidateGroupsMembership(userPrincipal); // Validate user's group membership against allowed/restricted groups
                if (errorItem != null) return errorItem; // Return immediately if validation fails

                errorItem = ValidatePasswordChangePermissions(userPrincipal); // Validate if user has permission to change password
                if (errorItem != null) return errorItem; // Return immediately if validation fails

                if (_options.UpdateLastPassword && userPrincipal.LastPasswordSet == null) // Check if 'UpdateLastPassword' option is enabled and LastPasswordSet is null
                {
                    errorItem = SetLastPassword(userPrincipal); // Update the 'pwdLastSet' attribute if conditions are met
                    if (errorItem != null) return errorItem; // Return immediately if setting LastPassword fails
                }

                if (!ValidateUserCredentials(userPrincipal.UserPrincipalName, currentPassword, principalContext)) // Validate provided current password
                {
                    LogInvalidCurrentPassword(_logger, fixedUsername, null);
                    return new ApiErrorItem(ApiErrorCode.InvalidCredentials); // Return error if current password is invalid
                }

                UpdatePassword(currentPassword, newPassword, userPrincipal); // Attempt to update the password

                userPrincipal.Save(); // Save changes to Active Directory
                LogPasswordSuccessfullyUpdated(_logger, fixedUsername, null);
            }
            catch (PasswordException passwordEx) // Catch exceptions related to password complexity policies
            {
                errorItem = new ApiErrorItem(ApiErrorCode.ComplexPassword, passwordEx.Message);
                LogPasswordChangeComplexityError(_logger, errorItem.Message ?? "Unknown error", passwordEx.Message, passwordEx);
            }
            catch (ApiErrorException apiErrorEx) // Catch custom API error exceptions
            {
                errorItem = apiErrorEx.ToApiErrorItem();
                LogPasswordChangeApiError(_logger, errorItem.Message ?? "Unknown error", apiErrorEx.Message, apiErrorEx);
            }
            catch (Exception ex) // Catch any other unexpected exceptions
            {
                errorItem = new ApiErrorItem(ApiErrorCode.Generic, ex.InnerException?.Message ?? ex.Message);
                LogPasswordChangeUnexpectedError(_logger, errorItem.Message ?? "Unknown error", ex.InnerException?.Message ?? ex.Message, ex);
            }

            return errorItem; // Return the error item, which will be null on success
        }

        /// <summary>
        /// Validates that the UserPrincipal object is not null.
        /// </summary>
        /// <param name="userPrincipal">The UserPrincipal object to validate.</param>
        /// <param name="fixedUsername">The username (used for logging purposes).</param>
        /// <returns>An <see cref="ApiErrorItem"/> if the UserPrincipal is null (user not found), otherwise null.</returns>
        private ApiErrorItem? ValidateUserPrincipal(UserPrincipal? userPrincipal, string fixedUsername)
        {
            if (userPrincipal == null) // Check if UserPrincipal is null
            {
                LogUserPrincipalNotFound(_logger, fixedUsername, null);
                return new ApiErrorItem(ApiErrorCode.UserNotFound); // Return UserNotFound error
            }
            return null; // UserPrincipal is valid
        }

        /// <summary>
        /// Validates the new password against the minimum password length policy of the domain.
        /// </summary>
        /// <param name="newPassword">The new password to validate.</param>
        /// <returns>An <see cref="ApiErrorItem"/> if the new password is too short, otherwise null.</returns>
        private ApiErrorItem? ValidateNewPasswordComplexity(string newPassword)
        {
            var minPasswordLength = AcquireDomainPasswordLength(); // Get minimum password length from domain policy
            if (newPassword.Length < minPasswordLength) // Check if new password length is less than the minimum
            {
                LogPasswordLengthTooShort(_logger, null);
                return new ApiErrorItem(ApiErrorCode.ComplexPassword); // Return ComplexPassword error
            }
            return null; // Password complexity is valid (length check passed)
        }

        /// <summary>
        /// Validates the new password against a list of known compromised passwords.
        /// Uses the PwnedPasswordsSearch library to check if the password has been compromised.
        /// </summary>
        /// <param name="newPassword">The new password to validate.</param>
        /// <returns>An <see cref="ApiErrorItem"/> if the new password is a known compromised password, otherwise null.</returns>
        private ApiErrorItem? ValidatePwnedPassword(string newPassword)
        {
            if (PwnedPasswordsSearch.PwnedSearch.IsPwnedPassword(newPassword)) // Check if password is in pwned password list
            {
                LogPwnedPasswordUsed(_logger, null);
                return new ApiErrorItem(ApiErrorCode.PwnedPassword); // Return PwnedPassword error
            }
            return null; // Password is not a known compromised password
        }

        /// <summary>
        /// Validates the user's group membership against configured allowed and restricted Active Directory groups.
        /// Password change is permitted only if the user is a member of an allowed group (if allowed groups are configured)
        /// and not a member of any restricted group (if restricted groups are configured).
        /// </summary>
        /// <param name="userPrincipal">The UserPrincipal object of the user.</param>
        /// <returns>An <see cref="ApiErrorItem"/> if group membership validation fails, otherwise null.</returns>
        private ApiErrorItem? ValidateGroupsMembership(UserPrincipal userPrincipal)
        {
            try
            {
                PrincipalSearchResult<Principal> groups; // Collection to hold user's groups
                try
                {
                    groups = userPrincipal.GetGroups(); // Attempt to retrieve groups using GetGroups (faster in some scenarios)
                }
                catch (Exception exception) // Catch exceptions during group retrieval
                {
                    LogErrorRetrievingGroups(_logger, exception.Message, exception);
                    groups = userPrincipal.GetAuthorizationGroups(); // Fallback to GetAuthorizationGroups if GetGroups fails (more reliable for cross-domain groups)
                }

                // Check for restricted group membership
                if (_options.RestrictedAdGroups != null && _options.RestrictedAdGroups.Any() && groups.Any(group => _options.RestrictedAdGroups.Contains(group.Name)))
                {
                    return new ApiErrorItem(ApiErrorCode.ChangeNotPermitted, "User is a member of a restricted group and password change is not permitted."); // Return error if in restricted group
                }

                // Check for allowed group membership (only if allowed groups are configured)
                // If AllowedAdGroups is null or empty, allow password change for all users not in restricted groups
                if (_options.AllowedAdGroups != null && _options.AllowedAdGroups.Any())
                {
                    if (!groups.Any(group => _options.AllowedAdGroups.Contains(group.Name))) // Check if user is a member of at least one allowed group
                    {
                        return new ApiErrorItem(ApiErrorCode.ChangeNotPermitted, "User is not a member of any allowed group and password change is not permitted."); // Return error if not in any allowed group
                    }
                }

                return null; // User is authorized based on group membership
            }
            catch (Exception exception) // Catch any exceptions during group validation
            {
                LogErrorGroupValidation(_logger, exception.Message, exception);
                return new ApiErrorItem(ApiErrorCode.Generic, "Error during group membership validation."); // Return error item to indicate validation failure
            }
        }

        /// <summary>
        /// Validates if the user is permitted to change their password based on the 'UserCannotChangePassword' flag in Active Directory.
        /// </summary>
        /// <param name="userPrincipal">The UserPrincipal object of the user.</param>
        /// <returns>An <see cref="ApiErrorItem"/> if the user is not permitted to change their password, otherwise null.</returns>
        private ApiErrorItem? ValidatePasswordChangePermissions(UserPrincipal userPrincipal)
        {
            if (userPrincipal.UserCannotChangePassword) // Check if the UserCannotChangePassword flag is set
            {
                LogPasswordChangeNotPermittedFlag(_logger, null);
                return new ApiErrorItem(ApiErrorCode.ChangeNotPermitted); // Return ChangeNotPermitted error
            }
            return null; // User is permitted to change password
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
            if (NativeMethods.LogonUser(upn, string.Empty, currentPassword, NativeMethods.LogonTypes.Network, NativeMethods.LogonProviders.Default, out _))
            {
                return true; // LogonUser succeeded, credentials validated
            }

            // Check for specific error codes indicating password expiration or must change scenarios
            var errorCode = System.Runtime.InteropServices.Marshal.GetLastWin32Error(); // Get the last Win32 error code
            LogValidateCredentialsWin32Error(_logger, errorCode, null);

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
        private ApiErrorItem? SetLastPassword(Principal userPrincipal)
        {
            var directoryEntry = (DirectoryEntry)userPrincipal.GetUnderlyingObject(); // Get the underlying DirectoryEntry object
            var pwdLastSetProperty = directoryEntry.Properties["pwdLastSet"]; // Get the 'pwdLastSet' property

            if (pwdLastSetProperty == null) // Check if 'pwdLastSet' property exists
            {
                LogPwdLastSetMissing(_logger, null);
                return new ApiErrorItem(ApiErrorCode.Generic, "The 'pwdLastSet' property is missing on the user principal."); // Return error item to indicate failure
            }

            try
            {
                pwdLastSetProperty.Value = -1; // Set 'pwdLastSet' to -1 to force password change at next logon
                directoryEntry.CommitChanges(); // Commit changes to Active Directory
                LogPwdLastSetUpdated(_logger, null);
                return null; // Indicate success
            }
            catch (Exception ex) // Catch exceptions during attribute update
            {
                LogPwdLastSetUpdateFailed(_logger, ex.Message, ex);
                return new ApiErrorItem(ApiErrorCode.ChangeNotPermitted, "Failed to update 'pwdLastSet' attribute."); // Return error item to indicate failure
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
            catch (Exception changePasswordException) // Catch exceptions during ChangePassword operation
            {
                if (_options.UseAutomaticContext) // If AutomaticContext is enabled, ChangePassword failure is critical
                {
                    LogChangePasswordAutomaticContextFailed(_logger, changePasswordException.Message, changePasswordException);
                    throw; // Re-throw the original exception - Password update is aborted in AutomaticContext mode if ChangePassword fails
                }

                try // Attempt to use SetPassword as a fallback if ChangePassword fails and AutomaticContext is disabled
                {
                    userPrincipal.SetPassword(newPassword); // Fallback to SetPassword method if ChangePassword fails
                    LogPasswordUpdatedSetPasswordFallback(_logger, changePasswordException);
                }
                catch (Exception setPasswordException) // Catch exceptions during SetPassword operation
                {
                    LogSetPasswordFailed(_logger, setPasswordException.Message, setPasswordException);
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
            LogIdentityTypeSet(_logger, _idType, null);
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
                LogAutomaticDomainContext(_logger, null); // Using existing delegate
                return new PrincipalContext(ContextType.Domain); // Create PrincipalContext using automatic domain context
            }
            else
            {
                if (!_options.LdapHostnames.Any()) // Check if LdapHostnames is empty when not using automatic context
                {
                    // Using logging delegate for warning about missing LDAP Hostnames
                    LogLdapHostnamesNotConfiguredWarning(_logger);
                    throw new InvalidOperationException("LDAP Hostnames are not configured."); // Throw exception to signal configuration error
                }

                var domain = $"{_options.LdapHostnames.First()}:{_options.LdapPort}"; // Construct domain string from hostname and port
                LogDomainContext(_logger, domain, null); // Using existing delegate
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
                    // Using logging delegate for error during PrincipalContext creation
                    LogPrincipalContextCreationFailedError(_logger, ex);
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
                    // Using logging delegate for warning about missing/invalid property
                    LogPasswordLengthRetrievalWarning(_logger, null);
                    return 6; // Default minimum password length
                }
            }
            catch (Exception ex)
            {
                // Using logging delegate for error during retrieval
                LogPasswordLengthRetrievalError(_logger, ex);
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
                // Use logging delegate for warning about missing LDAP Hostnames
                LogLdapHostnamesEmptyWarning(_logger, null);
                return null; // Return null to indicate failure to create DirectoryEntry
            }

            var domain = $"{_options.LdapHostnames.First()}:{_options.LdapPort}"; // Construct domain string
            LogCreatingDirectoryEntry(_logger, domain, null); // Already using delegate
            try
            {
                return new DirectoryEntry( // Create DirectoryEntry with LDAP credentials
                    domain,
                    _options.LdapUsername,
                    _options.LdapPassword);
            }
            catch (Exception ex)
            {
                // Use logging delegate for error during DirectoryEntry creation
                LogDirectoryEntryCreationFailedError(_logger, ex);
                return null; // Return null if DirectoryEntry creation fails
            }
        }
    }
}
#endif
