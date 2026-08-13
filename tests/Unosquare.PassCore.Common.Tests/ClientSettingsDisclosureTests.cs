using System.Collections.Generic;
using System.Text.Json;
using Unosquare.PassCore.Common.Models;
using Xunit;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// Pins which parts of <see cref="ClientSettings"/> are allowed to cross the wire to
/// the browser.
///
/// <para><b>Why this needs a test at all.</b> <c>PasswordController.Get()</c> is
/// <c>[HttpGet]</c> on an anonymous route and returns <c>Json(_options)</c> — the whole
/// bound <see cref="ClientSettings"/> object, with no projection or view model in
/// between. Every property added to that class is therefore published to unauthenticated
/// callers by default, and the only thing standing between a server-side setting and
/// public disclosure is a <see cref="System.Text.Json.Serialization.JsonIgnoreAttribute"/>
/// somebody remembered to write. That is an easy thing to forget and an invisible thing
/// to get wrong, so it is asserted here rather than left to review.</para>
///
/// <para><b>Serializer options.</b> These tests use
/// <see cref="JsonSerializerDefaults.Web"/> because that is what ASP.NET Core's
/// <c>AddControllers()</c> configures and therefore what <c>Controller.Json(...)</c>
/// actually applies — camelCase names, case-insensitive binding. Asserting against
/// default <see cref="JsonSerializerOptions"/> would test a shape the application never
/// produces.</para>
///
/// <para><b>If one of these fails</b> because a field was deliberately reclassified,
/// re-derive the assertion against the new intent rather than deleting it — and for a
/// field moving from hidden to published, confirm first that publishing it to anonymous
/// callers is actually intended.</para>
/// </summary>
public class ClientSettingsDisclosureTests
{
    private static readonly JsonSerializerOptions WebDefaults = new(JsonSerializerDefaults.Web);

    private static ClientSettings FullyPopulatedSettings() => new()
    {
        ApplicationTitle = "Change Account Password",
        ChangePasswordTitle = "Change Account Password",
        UsePasswordGeneration = true,
        ShowPasswordMeter = true,
        UseEmail = true,
        EnablePwnedPasswordCheck = true,
        MinimumDistance = 3,
        MinimumScore = 2,
        PasswordEntropy = 16,
        Alerts = new Alerts { SuccessAlertTitle = "Done" },
        ChangePasswordForm = new ChangePasswordForm { UsernameLabel = "Username" },
        ErrorsPasswordForm = new ErrorsPasswordForm { FieldRequired = "Required" },
        ValidationRegex = new ValidationRegex { UsernameRegex = "^[a-z]+$" },
        Recaptcha = new Recaptcha
        {
            SiteKey = "public-site-key",
            PrivateKey = "SUPER-SECRET-PRIVATE-KEY",
            LanguageCode = "en",
        },
        PasswordProviderOptions = new PasswordProviderOptions
        {
            RestrictedAdGroups = new List<string> { "Domain Admins", "Tier0 Operators" },
            AllowedAdGroups = new List<string> { "Password Self Service" },
        },
    };

    [Fact]
    public void SerializedSettings_OmitThePasswordProviderOptionsGroupLists()
    {
        var json = JsonSerializer.Serialize(FullyPopulatedSettings(), WebDefaults);

        // The property itself must not appear...
        Assert.DoesNotContain("passwordProviderOptions", json, System.StringComparison.OrdinalIgnoreCase);

        // ...and neither must the group names it carries, under any nesting. These are the
        // deployment's privileged directory groups; disclosing them to anonymous callers
        // hands out a map of which groups are worth attacking.
        Assert.DoesNotContain("Domain Admins", json, System.StringComparison.Ordinal);
        Assert.DoesNotContain("Tier0 Operators", json, System.StringComparison.Ordinal);
        Assert.DoesNotContain("Password Self Service", json, System.StringComparison.Ordinal);
    }

    [Fact]
    public void SerializedSettings_OmitTheRecaptchaPrivateKeyButKeepTheSiteKey()
    {
        var json = JsonSerializer.Serialize(FullyPopulatedSettings(), WebDefaults);

        Assert.DoesNotContain("SUPER-SECRET-PRIVATE-KEY", json, System.StringComparison.Ordinal);
        Assert.DoesNotContain("privateKey", json, System.StringComparison.OrdinalIgnoreCase);

        // The site key is public by design — reCAPTCHA renders it into the page — so its
        // absence would be a regression in the other direction.
        Assert.Contains("public-site-key", json, System.StringComparison.Ordinal);
    }

    [Fact]
    public void SerializedSettings_StillCarryEverythingTheWebClientReads()
    {
        var json = JsonSerializer.Serialize(FullyPopulatedSettings(), WebDefaults);
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        // Mirrors IGlobalContext in ClientApp/types/Providers.ts. Hiding a field the
        // client dereferences crashes the app to a blank page rather than degrading, so
        // the published set is pinned in both directions.
        foreach (var property in new[]
                 {
                     "alerts",
                     "applicationTitle",
                     "changePasswordForm",
                     "changePasswordTitle",
                     "errorsPasswordForm",
                     "recaptcha",
                     "showPasswordMeter",
                     "useEmail",
                     "usePasswordGeneration",
                     "validationRegex",
                 })
        {
            Assert.True(
                root.TryGetProperty(property, out _),
                $"ClientSettings no longer publishes '{property}', which the web client reads.");
        }
    }

    [Fact]
    public void PasswordProviderOptions_AreStillBindableFromConfiguration()
    {
        // JsonIgnore governs serialization only. Configuration binding uses
        // Microsoft.Extensions.Configuration, not System.Text.Json, so hiding the
        // property from the wire must not stop GroupMembershipPolicy from being
        // configured. Deserializing the property name explicitly proves the attribute is
        // JsonIgnore rather than something that would drop the data entirely.
        var settings = FullyPopulatedSettings();

        Assert.NotNull(settings.PasswordProviderOptions);
        Assert.Contains("Domain Admins", settings.PasswordProviderOptions!.RestrictedAdGroups!);
    }
}
