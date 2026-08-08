using Unosquare.PassCore.Common.Models;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Contains all the details of a password change request.
/// </summary>
public class PasswordChangeContext
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordChangeContext"/> class.
    /// </summary>
    /// <param name="username">The username requesting password change.</param>
    /// <param name="currentPassword">The user's current password.</param>
    /// <param name="newPassword">The user's new password.</param>
    /// <param name="clientSettings">The settings for password validation.</param>
    /// <param name="correlationId">The optional correlation ID for request tracing.</param>
    public PasswordChangeContext(string username, string currentPassword, string newPassword, ClientSettings clientSettings, string? correlationId = null)
    {
        Username = username;
        CurrentPassword = currentPassword;
        NewPassword = newPassword;
        ClientSettings = clientSettings;
        CorrelationId = correlationId;
    }

    /// <summary>Gets the username requesting password change.</summary>
    public string Username { get; }

    /// <summary>Gets the user's current password.</summary>
    public string CurrentPassword { get; }

    /// <summary>Gets the user's new password.</summary>
    public string NewPassword { get; }

    /// <summary>Gets the settings for password validation.</summary>
    public ClientSettings ClientSettings { get; }

    /// <summary>Gets the optional correlation ID for request tracing.</summary>
    public string? CorrelationId { get; }
}
