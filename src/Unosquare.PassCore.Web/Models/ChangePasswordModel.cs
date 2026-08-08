using System.ComponentModel.DataAnnotations;

namespace Unosquare.PassCore.Web.Models;

/// <summary>
/// Model representing the request payload for password change.
/// </summary>
public class ChangePasswordModel
{
    private string? _username;
    private string? _currentPassword;
    private string? _newPassword;
    private string? _newPasswordVerify;
    private string? _recaptcha;

    /// <summary>Gets or sets the username.</summary>
    [Required(ErrorMessage = nameof(ApiErrorCode.FieldRequired))]
    public string Username
    {
        get => _username ?? string.Empty;
        set => _username = value;
    }

    /// <summary>Gets or sets the current password.</summary>
    [Required(ErrorMessage = nameof(ApiErrorCode.FieldRequired))]
    public string CurrentPassword
    {
        get => _currentPassword ?? string.Empty;
        set => _currentPassword = value;
    }

    /// <summary>Gets or sets the new password.</summary>
    [Required(ErrorMessage = nameof(ApiErrorCode.FieldRequired))]
    public string NewPassword
    {
        get => _newPassword ?? string.Empty;
        set => _newPassword = value;
    }

    /// <summary>Gets or sets the verification of the new password.</summary>
    [Required(ErrorMessage = nameof(ApiErrorCode.FieldRequired))]
    [Compare(nameof(NewPassword), ErrorMessage = nameof(ApiErrorCode.FieldMismatch))]
    public string NewPasswordVerify
    {
        get => _newPasswordVerify ?? string.Empty;
        set => _newPasswordVerify = value;
    }

    /// <summary>Gets or sets the reCAPTCHA token response.</summary>
    public string Recaptcha
    {
        get => _recaptcha ?? string.Empty;
        set => _recaptcha = value;
    }
}