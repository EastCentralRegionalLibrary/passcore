namespace Unosquare.PassCore.Common;

/// <summary>
/// Represents the context for a password change operation.
/// </summary>
public class PasswordChangeContext
{
    /// <summary>
    /// Gets or sets the username.
    /// </summary>
    public string Username { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the current password.
    /// </summary>
    public string CurrentPassword { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the new password.
    /// </summary>
    public string NewPassword { get; set; } = string.Empty;

    /// <summary>
    /// Gets or sets the client settings.
    /// </summary>
    public ClientSettings? ClientSettings { get; set; }
}
