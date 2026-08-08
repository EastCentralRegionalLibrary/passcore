namespace Unosquare.PassCore.Common.Models;

/// <summary>
/// Configuration for the change password form field labels and help text.
/// </summary>
public class ChangePasswordForm
{
    /// <summary>Gets or sets the change password button label.</summary>
    public string? ChangePasswordButtonLabel { get; set; }

    /// <summary>Gets or sets the current password help block text.</summary>
    public string? CurrentPasswordHelpblock { get; set; }

    /// <summary>Gets or sets the current password label.</summary>
    public string? CurrentPasswordLabel { get; set; }

    /// <summary>Gets or sets the help text displayed on the form.</summary>
    public string? HelpText { get; set; }

    /// <summary>Gets or sets the new password help block text.</summary>
    public string? NewPasswordHelpblock { get; set; }

    /// <summary>Gets or sets the new password label.</summary>
    public string? NewPasswordLabel { get; set; }

    /// <summary>Gets or sets the new password verify help block text.</summary>
    public string? NewPasswordVerifyHelpblock { get; set; }

    /// <summary>Gets or sets the new password verify label.</summary>
    public string? NewPasswordVerifyLabel { get; set; }

    /// <summary>Gets or sets the helper block text for the default domain.</summary>
    public string? UsernameDefaultDomainHelperBlock { get; set; }

    /// <summary>Gets or sets the username help block text.</summary>
    public string? UsernameHelpblock { get; set; }

    /// <summary>Gets or sets the username label.</summary>
    public string? UsernameLabel { get; set; }
}
