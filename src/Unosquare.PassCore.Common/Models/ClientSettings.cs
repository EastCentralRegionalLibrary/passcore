using System.Text.Json.Serialization;
using System.Collections.Generic;

namespace Unosquare.PassCore.Common.Models;

/// <summary>
/// Represents all of the strongly-typed application settings loaded from a JSON file.
/// </summary>
public class ClientSettings
{
    /// <summary>Gets or sets the alert configuration.</summary>
    public Alerts? Alerts { get; set; }

    /// <summary>Gets or sets a value indicating whether password generation is enabled.</summary>
    public bool UsePasswordGeneration { get; set; }

    /// <summary>Gets or sets the minimum distance required between old and new passwords.</summary>
    public int MinimumDistance { get; set; }

    /// <summary>Gets or sets the password entropy setting.</summary>
    public int PasswordEntropy { get; set; }

    /// <summary>Gets or sets the minimum score requirement.</summary>
    public int MinimumScore { get; set; }

    /// <summary>Gets or sets a value indicating whether to show the password meter.</summary>
    public bool ShowPasswordMeter { get; set; }

    /// <summary>Gets or sets a value indicating whether to use email.</summary>
    public bool UseEmail { get; set; }

    /// <summary>Gets or sets a value indicating whether pwned password checks are enabled.</summary>
    public bool EnablePwnedPasswordCheck { get; set; }

    /// <summary>Gets or sets the configuration for the change password form.</summary>
    public ChangePasswordForm? ChangePasswordForm { get; set; }

    /// <summary>Gets or sets the error messages for the password form.</summary>
    public ErrorsPasswordForm? ErrorsPasswordForm { get; set; }

    /// <summary>Gets or sets the Recaptcha settings.</summary>
    public Recaptcha? Recaptcha { get; set; }

    /// <summary>Gets or sets the application title.</summary>
    public string? ApplicationTitle { get; set; }

    /// <summary>Gets or sets the title for change password page.</summary>
    public string? ChangePasswordTitle { get; set; }

    /// <summary>Gets or sets validation regular expressions.</summary>
    public ValidationRegex? ValidationRegex { get; set; }

    /// <summary>Gets or sets extended settings for policies.</summary>
    /// <remarks>
    /// Server-side only, and deliberately excluded from the JSON the browser receives.
    /// This whole object is bound from the <c>ClientSettings</c> configuration section
    /// for the convenience of sharing one options class, but it is consumed exclusively
    /// by <see cref="Policies.GroupMembershipPolicy"/>; no part of the web client reads
    /// it. Without this attribute the anonymous <c>GET /api/password</c> endpoint hands
    /// every visitor the deployment's restricted and allowed directory group names,
    /// which describes the directory's privileged-group topology to anyone who asks.
    /// <para><see cref="System.Text.Json"/> attributes affect serialization only;
    /// configuration binding does not go through <c>System.Text.Json</c>, so this does
    /// not stop the section from being populated. <see cref="Recaptcha.PrivateKey"/> is
    /// protected the same way.</para>
    /// </remarks>
    [JsonIgnore]
    public PasswordProviderOptions? PasswordProviderOptions { get; set; }
}

/// <summary>
/// Policy settings for Active Directory / LDAP groups.
/// </summary>
public class PasswordProviderOptions
{
    /// <summary>Gets or sets the collection of restricted group names.</summary>
    public IReadOnlyCollection<string>? RestrictedAdGroups { get; set; }

    /// <summary>Gets or sets the collection of allowed group names.</summary>
    public IReadOnlyCollection<string>? AllowedAdGroups { get; set; }
}

/// <summary>
/// Configuration settings for Google reCAPTCHA.
/// </summary>
public class Recaptcha
{
    /// <summary>Gets or sets the reCAPTCHA language code.</summary>
    public string? LanguageCode { get; set; }

    /// <summary>Gets or sets the site key.</summary>
    public string? SiteKey { get; set; }

    /// <summary>Gets or sets the private key.</summary>
    [JsonIgnore]
    public string? PrivateKey { get; set; }
}

/// <summary>
/// Text configurations for UI alerts.
/// </summary>
public class Alerts
{
    /// <summary>Gets or sets the error message for invalid credentials.</summary>
    public string? ErrorInvalidCredentials { get; set; }

    /// <summary>Gets or sets the error message for invalid domains.</summary>
    public string? ErrorInvalidDomain { get; set; }

    /// <summary>Gets or sets the error message when password changes are not allowed.</summary>
    public string? ErrorPasswordChangeNotAllowed { get; set; }

    /// <summary>Gets or sets the success alert body text.</summary>
    public string? SuccessAlertBody { get; set; }

    /// <summary>Gets or sets the success alert title.</summary>
    public string? SuccessAlertTitle { get; set; }

    /// <summary>Gets or sets the error message for an invalid user.</summary>
    public string? ErrorInvalidUser { get; set; }

    /// <summary>Gets or sets the error message for reCAPTCHA failure.</summary>
    public string? ErrorCaptcha { get; set; }

    /// <summary>Gets or sets the error message for required fields.</summary>
    public string? ErrorFieldRequired { get; set; }

    /// <summary>Gets or sets the error message for field mismatch.</summary>
    public string? ErrorFieldMismatch { get; set; }

    /// <summary>Gets or sets the error message for complex password requirements.</summary>
    public string? ErrorComplexPassword { get; set; }

    /// <summary>Gets or sets the error message for LDAP connection issues.</summary>
    public string? ErrorConnectionLdap { get; set; }

    /// <summary>Gets or sets the error message for a weak password score.</summary>
    public string? ErrorScorePassword { get; set; }

    /// <summary>Gets or sets the error message for password distance.</summary>
    public string? ErrorDistancePassword { get; set; }

    /// <summary>Gets or sets the error message for a pwned password.</summary>
    public string? ErrorPwnedPassword { get; set; }
}

/// <summary>
/// Custom error messages shown on the change password form.
/// </summary>
public class ErrorsPasswordForm
{
    /// <summary>Gets or sets the message for a required field.</summary>
    public string? FieldRequired { get; set; }

    /// <summary>Gets or sets the message when passwords do not match.</summary>
    public string? PasswordMatch { get; set; }

    /// <summary>Gets or sets the message when username/email format is invalid.</summary>
    public string? UsernameEmailPattern { get; set; }

    /// <summary>Gets or sets the message when username pattern is invalid.</summary>
    public string? UsernamePattern { get; set; }
}

/// <summary>
/// Regular expression configurations for inputs validation.
/// </summary>
public class ValidationRegex
{
    /// <summary>Gets or sets the email regex pattern.</summary>
    public string? EmailRegex { get; set; }

    /// <summary>Gets or sets the username regex pattern.</summary>
    public string? UsernameRegex { get; set; }
}
