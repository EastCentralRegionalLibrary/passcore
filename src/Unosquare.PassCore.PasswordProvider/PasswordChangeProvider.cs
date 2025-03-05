using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using System;
using System.DirectoryServices;
using System.DirectoryServices.AccountManagement;
using System.DirectoryServices.ActiveDirectory;
using System.Linq;
using Unosquare.PassCore.Common;

namespace Unosquare.PassCore.PasswordProvider;

/// <inheritdoc />
/// <summary>
/// Default Change Password Provider using 'System.DirectoryServices' from Microsoft.
/// Implements the <see cref="IPasswordChangeProvider"/> interface to provide password change functionality
/// against Active Directory using the System.DirectoryServices and System.DirectoryServices.AccountManagement namespaces.
/// </summary>
/// <seealso cref="IPasswordChangeProvider" />
public class PasswordChangeProvider : IPasswordChangeProvider
{
    private readonly PasswordChangeOptions _options;
    private readonly ILogger<PasswordChangeProvider> _logger;
    private IdentityType _idType = IdentityType.UserPrincipalName; // Default identity type

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
            _logger.LogInformation($"Performing password change for user '{fixedUsername}'.");

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
                SetLastPassword(userPrincipal); // Update the 'pwdLastSet' attribute if conditions are met
                if (errorItem != null) return errorItem; // Return immediately if setting LastPassword fails
            }

            if (!ValidateUserCredentials(userPrincipal.UserPrincipalName, currentPassword, principalContext)) // Validate provided current password
            {
                _logger.LogWarning($"Invalid current password provided for user '{fixedUsername}'.");
                return new ApiErrorItem(ApiErrorCode.InvalidCredentials); // Return error if current password is invalid
            }

            UpdatePassword(currentPassword, newPassword, userPrincipal); // Attempt to update the password

            userPrincipal.Save(); // Save changes to Active Directory
            _logger.LogDebug($"Password successfully updated for user '{fixedUsername}'.");
        }
        catch (PasswordException passwordEx) // Catch exceptions related to password complexity policies
        {
            errorItem = new ApiErrorItem(ApiErrorCode.ComplexPassword, passwordEx.Message);
            _logger.LogWarning(passwordEx, "Password change failed due to complexity policies: {ErrorMessage}", errorItem.Message);
        }
        catch (ApiErrorException apiErrorEx) // Catch custom API error exceptions
        {
            errorItem = apiErrorEx.ToApiErrorItem();
            _logger.LogWarning(apiErrorEx, "Password change failed due to API error: {ErrorMessage}", errorItem.Message);
        }
        catch (Exception ex) // Catch any other unexpected exceptions
        {
            errorItem = new ApiErrorItem(ApiErrorCode.Generic, ex.InnerException?.Message ?? ex.Message);
            _logger.LogError(ex, "Password change failed due to an unexpected error: {ErrorMessage}", errorItem.Message);
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
            _logger.LogWarning($"User principal '{fixedUsername}' not found.");
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
            _logger.LogError("New password length is shorter than the Active Directory minimum password length.");
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
            _logger.LogError("New password is a known compromised password and is not allowed.");
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
                _logger.LogError(new EventId(887), exception, "Error retrieving user groups using GetGroups. Falling back to GetAuthorizationGroups.");
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
            _logger.LogError(new EventId(888), exception, "Error during group membership validation: {ErrorMessage}", exception.Message);
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
            _logger.LogWarning("User is not permitted to change their password.");
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
        _logger.LogDebug($"ValidateUserCredentials GetLastWin32Error {errorCode}");

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
            _logger.LogWarning("The 'pwdLastSet' property is missing on the user principal.");
            return new ApiErrorItem(ApiErrorCode.Generic, "The 'pwdLastSet' property is missing on the user principal."); // Return error item to indicate failure
        }

        try
        {
            pwdLastSetProperty.Value = -1; // Set 'pwdLastSet' to -1 to force password change at next logon
            directoryEntry.CommitChanges(); // Commit changes to Active Directory
            _logger.LogInformation("The 'pwdLastSet' attribute was successfully updated.");
            return null; // Indicate success
        }
        catch (Exception ex) // Catch exceptions during attribute update
        {
            _logger.LogError(ex, "Failed to update 'pwdLastSet' attribute: {ErrorMessage}", ex.Message);
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
                _logger.LogWarning(changePasswordException, "ChangePassword failed with AutomaticContext enabled. Password update aborted.");
                throw; // Re-throw the original exception - Password update is aborted in AutomaticContext mode if ChangePassword fails
            }

            try // Attempt to use SetPassword as a fallback if ChangePassword fails and AutomaticContext is disabled
            {
                userPrincipal.SetPassword(newPassword); // Fallback to SetPassword method if ChangePassword fails
                _logger.LogDebug("Password updated using SetPassword method after ChangePassword failure.");
            }
            catch (Exception setPasswordException) // Catch exceptions during SetPassword operation
            {
                _logger.LogError(setPasswordException, "SetPassword failed after ChangePassword failure. Password update failed.");
                throw; // Re-throw the SetPassword exception as password update ultimately failed
            }
        }
    }


    /// <summary>
    /// Sets the identity type based on configuration options, providing fault tolerance for various string inputs.
    /// Uses a switch expression to map string configuration values to <see cref="IdentityType"/> enum values.
    /// Defaults to <see cref="IdentityType.UserPrincipalName"/> if no match is found.
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
        _logger.LogDebug($"Identity type set to '{_idType}'.");
    }

    /// <summary>
    /// Acquires a PrincipalContext object for Active Directory operations.
    /// If 'UseAutomaticContext' is enabled, it uses the automatic domain context.
    /// Otherwise, it creates a context based on LDAP hostname, port, username, and password from options.
    /// </summary>
    /// <returns>A <see cref="PrincipalContext"/> object for Active Directory interaction.</returns>
    private PrincipalContext AcquirePrincipalContext()
    {
        if (_options.UseAutomaticContext) // Check if automatic context is enabled
        {
            _logger.LogDebug("Using automatic domain context.");
            return new PrincipalContext(ContextType.Domain); // Create PrincipalContext using automatic domain context
        }

        // Create PrincipalContext using provided LDAP hostname and credentials
        var domain = $"{_options.LdapHostnames.First()}:{_options.LdapPort}"; // Construct domain string from hostname and port
        _logger.LogDebug($"Using domain context: '{domain}'.");
        return new PrincipalContext(
            ContextType.Domain,
            domain,
            _options.LdapUsername,
            _options.LdapPassword);
    }

    /// <summary>
    /// Retrieves the minimum password length policy from Active Directory.
    /// Uses either automatic domain context or specified LDAP connection details based on 'UseAutomaticContext' option.
    /// </summary>
    /// <returns>The minimum password length as an integer.</returns>
    private int AcquireDomainPasswordLength()
    {
        DirectoryEntry entry = _options.UseAutomaticContext // Determine DirectoryEntry creation method based on UseAutomaticContext
            ? Domain.GetCurrentDomain().GetDirectoryEntry() // Get DirectoryEntry using automatic domain context
            : GetDirectoryEntry(); // Use extracted method to get DirectoryEntry with LDAP credentials

        return (int)entry.Properties["minPwdLength"].Value; // Retrieve minimum password length from 'minPwdLength' property
    }

    /// <summary>
    /// Creates and returns a DirectoryEntry object using LDAP connection details from options.
    /// This method is extracted for better readability and reusability.
    /// </summary>
    /// <returns>A <see cref="DirectoryEntry"/> object configured with LDAP credentials.</returns>
    private DirectoryEntry GetDirectoryEntry() // Extracted method for DirectoryEntry creation
    {
        var domain = $"{_options.LdapHostnames.First()}:{_options.LdapPort}"; // Construct domain string
        _logger.LogDebug($"Creating DirectoryEntry for domain: '{domain}'.");
        return new DirectoryEntry( // Create DirectoryEntry with LDAP credentials
            domain,
            _options.LdapUsername,
            _options.LdapPassword);
    }
}