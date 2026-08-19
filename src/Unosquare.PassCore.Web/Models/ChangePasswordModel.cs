using System.ComponentModel.DataAnnotations;

namespace Unosquare.PassCore.Web.Models;

/// <summary>
/// Model representing the request payload for password change.
/// </summary>
public class ChangePasswordModel
{
    /// <summary>Maximum allowed character length for the username field.</summary>
    public const int MaxUsernameLength = 512;

    /// <summary>Maximum allowed character length for password fields.</summary>
    public const int MaxPasswordLength = 1024;

    /// <summary>Maximum allowed character length for the reCAPTCHA token field.</summary>
    public const int MaxRecaptchaLength = 8192;

    private string? _username;
    private string? _currentPassword;
    private string? _newPassword;
    private string? _newPasswordVerify;
    private string? _recaptcha;

    /// <summary>Gets or sets the username.</summary>
    [Required(ErrorMessage = nameof(ApiErrorCode.FieldRequired))]
    [StringLength(MaxUsernameLength)]
    public string Username
    {
        get => _username ?? string.Empty;
        set => _username = value;
    }

    /// <summary>Gets or sets the current password.</summary>
    [Required(ErrorMessage = nameof(ApiErrorCode.FieldRequired))]
    [StringLength(MaxPasswordLength)]
    public string CurrentPassword
    {
        get => _currentPassword ?? string.Empty;
        set => _currentPassword = value;
    }

    /// <summary>Gets or sets the new password.</summary>
    [Required(ErrorMessage = nameof(ApiErrorCode.FieldRequired))]
    [StringLength(MaxPasswordLength)]
    public string NewPassword
    {
        get => _newPassword ?? string.Empty;
        set => _newPassword = value;
    }

    /// <summary>Gets or sets the verification of the new password.</summary>
    [Required(ErrorMessage = nameof(ApiErrorCode.FieldRequired))]
    [Compare(nameof(NewPassword), ErrorMessage = nameof(ApiErrorCode.FieldMismatch))]
    [StringLength(MaxPasswordLength)]
    public string NewPasswordVerify
    {
        get => _newPasswordVerify ?? string.Empty;
        set => _newPasswordVerify = value;
    }

    /// <summary>Gets or sets the reCAPTCHA token response.</summary>
    [StringLength(MaxRecaptchaLength)]
    public string Recaptcha
    {
        get => _recaptcha ?? string.Empty;
        set => _recaptcha = value;
    }
}
