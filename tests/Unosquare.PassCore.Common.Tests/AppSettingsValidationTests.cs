using System;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// Both providers repeated the same three checks -- hostnames, service account
/// username, service account password -- with only "is this required at all"
/// differing between them (AD only when not using automatic context, LDAP always).
/// These tests pin the shared validator's behavior for both answers.
/// </summary>
public class AppSettingsValidationTests
{
    private sealed class FakeAppSettings : IAppSettings
    {
        public ErrorDisclosureMode ErrorDisclosureMode { get; set; }

        public bool AllowAdministrativeReset { get; set; }

        public string DefaultDomain { get; set; } = string.Empty;

        public int LdapPort { get; set; }

        public string[] LdapHostnames { get; set; } = Array.Empty<string>();

        public string LdapPassword { get; set; } = string.Empty;

        public string LdapUsername { get; set; } = string.Empty;
    }

    private static FakeAppSettings ValidSettings() => new()
    {
        LdapHostnames = new[] { "dc1.example.com" },
        LdapUsername = "svc-account",
        LdapPassword = "hunter2",
    };

    [Fact]
    public void NotRequired_AllBlankHostnames_DoesNotThrow()
    {
        var settings = ValidSettings();
        settings.LdapHostnames = new[] { "", "   " };

        AppSettingsValidation.ValidateServiceAccount(settings, required: false);
    }

    [Fact]
    public void Required_NullHostnames_Throws()
    {
        var settings = ValidSettings();
        settings.LdapHostnames = null!;

        var ex = Assert.Throws<ArgumentException>(
            () => AppSettingsValidation.ValidateServiceAccount(settings, required: true));

        Assert.Equal("Hostnames are not configured.", ex.Message);
    }

    [Fact]
    public void Required_EmptyHostnamesArray_Throws()
    {
        var settings = ValidSettings();
        settings.LdapHostnames = Array.Empty<string>();

        var ex = Assert.Throws<ArgumentException>(
            () => AppSettingsValidation.ValidateServiceAccount(settings, required: true));

        Assert.Equal("Hostnames are not configured.", ex.Message);
    }

    [Fact]
    public void Required_SingleBlankHostname_Throws()
    {
        var settings = ValidSettings();
        settings.LdapHostnames = new[] { "" };

        var ex = Assert.Throws<ArgumentException>(
            () => AppSettingsValidation.ValidateServiceAccount(settings, required: true));

        Assert.Equal("Hostnames are not configured.", ex.Message);
    }

    /// <summary>
    /// Null, empty, and all-blank hostname arrays are indistinguishable failures and
    /// must produce the exact same message.
    /// </summary>
    [Fact]
    public void Required_NullEmptyAndBlankHostnames_ProduceTheSameMessage()
    {
        var nullEx = Assert.Throws<ArgumentException>(() =>
        {
            var settings = ValidSettings();
            settings.LdapHostnames = null!;
            AppSettingsValidation.ValidateServiceAccount(settings, required: true);
        });

        var emptyEx = Assert.Throws<ArgumentException>(() =>
        {
            var settings = ValidSettings();
            settings.LdapHostnames = Array.Empty<string>();
            AppSettingsValidation.ValidateServiceAccount(settings, required: true);
        });

        var blankEx = Assert.Throws<ArgumentException>(() =>
        {
            var settings = ValidSettings();
            settings.LdapHostnames = new[] { "" };
            AppSettingsValidation.ValidateServiceAccount(settings, required: true);
        });

        Assert.Equal(nullEx.Message, emptyEx.Message);
        Assert.Equal(emptyEx.Message, blankEx.Message);
    }

    /// <summary>
    /// A mixed array with at least one non-blank entry is out of scope for blank
    /// filtering -- it must not throw.
    /// </summary>
    [Fact]
    public void Required_MixedHostnamesWithOneNonBlankEntry_DoesNotThrow()
    {
        var settings = ValidSettings();
        settings.LdapHostnames = new[] { "", "dc1" };

        AppSettingsValidation.ValidateServiceAccount(settings, required: true);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Required_BlankUsername_Throws(string? username)
    {
        var settings = ValidSettings();
        settings.LdapUsername = username!;

        var ex = Assert.Throws<ArgumentException>(
            () => AppSettingsValidation.ValidateServiceAccount(settings, required: true));

        Assert.Equal("Service account username is not configured.", ex.Message);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Required_BlankPassword_Throws(string? password)
    {
        var settings = ValidSettings();
        settings.LdapPassword = password!;

        var ex = Assert.Throws<ArgumentException>(
            () => AppSettingsValidation.ValidateServiceAccount(settings, required: true));

        Assert.Equal("Service account password is not configured.", ex.Message);
    }

    [Fact]
    public void Required_ValidSettings_DoesNotThrow()
    {
        AppSettingsValidation.ValidateServiceAccount(ValidSettings(), required: true);
    }

    [Fact]
    public void NullSettings_Throws()
    {
        Assert.Throws<ArgumentNullException>(
            () => AppSettingsValidation.ValidateServiceAccount(null!, required: true));
    }
}
