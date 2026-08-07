using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using System.Threading.Tasks;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Models;
using Xunit;
using static Unosquare.PassCore.Testing.RepositorySource;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// A stock deployment must accept the username form its own UI asks for.
/// <c>src/Unosquare.PassCore.Web/appsettings.json</c> ships
/// <c>DefaultDomain: ""</c> alongside <c>UseEmail: true</c> and a username help
/// block reading "Your organization's email address", so an unmodified install
/// prompts for <c>user@domain</c> and must resolve it.
///
/// <para>These tests read the shipped file rather than constructing options in
/// code: the failure being guarded against is a configuration/behavior
/// contradiction, and a hand-built options object cannot express one. Only the
/// values under test come from the file — <c>DefaultDomain</c>, the search
/// filter, and the client-side username form. The connection settings are
/// filled in here because the shipped file deliberately leaves them blank for
/// the operator, and <c>ValidateOptions</c> rejects blanks at construction.</para>
/// </summary>
public class ShippedConfigurationUsernameFormTests
{
    private const string AppSettingsRelativePath = "src/Unosquare.PassCore.Web/appsettings.json";

    private const string EmailFormUsername = "jdoe@example.com";

    /// <summary>
    /// The premise the rest of this class rests on. If the shipped defaults ever
    /// change — a default domain is set, or the UI stops asking for an email
    /// address — the tests below are guarding a situation that no longer exists
    /// and should be revisited rather than silently kept passing.
    /// </summary>
    [Fact]
    public void ShippedConfiguration_AsksForAnEmailAddressAndConfiguresNoDefaultDomain()
    {
        var settings = ShippedSettings();

        Assert.True(
            string.IsNullOrEmpty(settings.DefaultDomain),
            $"appsettings.json now ships DefaultDomain='{settings.DefaultDomain}'. These tests exist " +
            "because it ships empty while the UI asks for an email address; re-derive them against " +
            "the new default.");

        Assert.True(
            settings.UseEmail,
            "appsettings.json no longer ships UseEmail=true, so the shipped UI may no longer be " +
            "asking for a qualified username. Re-derive these tests against the new default.");

        Assert.Contains("email", settings.UsernameHelpblock, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// The end-to-end path on the LDAP provider: an email-form username, the
    /// shipped (empty) default domain, and the shipped search filter must
    /// resolve the account rather than being rejected as a malformed username.
    /// A rejection surfaces as <c>InvalidCredentials</c>, indistinguishable from
    /// a wrong password, with nothing to point the operator at configuration.
    /// </summary>
    [Fact]
    public async Task ShippedConfiguration_EmailFormUsername_ResolvesOnTheLdapProvider()
    {
        var settings = ShippedSettings();
        var provider = ProviderWithShippedUsernameSettings(settings, out var filters);

        // The user is found, so membership evaluation runs to a real answer; a
        // sanitizer rejection would instead throw out of the call.
        Assert.True(await provider.IsMemberOfGroupAsync(EmailFormUsername, "DirectGroup"));

        // The shipped filter is sAMAccountName-shaped, which matches the bare
        // account name — the qualifier is dropped for the search, not smuggled in.
        Assert.Equal("(sAMAccountName=jdoe)", filters[0]);
    }

    /// <summary>
    /// Same path, spelled <c>DOMAIN\user</c>. The shipped UI asks for an email
    /// address, but a domain-qualified username is what a Windows-trained user
    /// types, and it was accepted before the qualifier validation was added.
    /// </summary>
    [Fact]
    public async Task ShippedConfiguration_NetbiosFormUsername_ResolvesOnTheLdapProvider()
    {
        var settings = ShippedSettings();
        var provider = ProviderWithShippedUsernameSettings(settings, out var filters);

        Assert.True(await provider.IsMemberOfGroupAsync("EXAMPLE\\jdoe", "DirectGroup"));
        Assert.Equal("(sAMAccountName=jdoe)", filters[0]);
    }

    /// <summary>
    /// The counterpart to the two above, and the behavior that must survive:
    /// once an operator configures a default domain, a username qualified with a
    /// different one is rejected.
    /// </summary>
    [Fact]
    public async Task ConfiguredDefaultDomain_ForeignQualifier_IsStillRejected()
    {
        var settings = ShippedSettings() with { DefaultDomain = "example.com" };
        var provider = ProviderWithShippedUsernameSettings(settings, out _);

        var error = await Assert.ThrowsAsync<Unosquare.PassCore.Common.Exceptions.InvalidCredentialsException>(
            () => provider.IsMemberOfGroupAsync("jdoe@other.com", "DirectGroup"));

        Assert.Equal(ApiErrorCode.InvalidCredentials, ApiErrorMapper.Map(error).ErrorCode);
    }

    /// <summary>
    /// Builds a provider whose username-relevant configuration is the shipped
    /// one, backed by a directory that holds exactly one account: <c>jdoe</c>,
    /// a member of <c>DirectGroup</c>. <paramref name="filters"/> collects every
    /// search filter the provider issues, in order.
    /// </summary>
    private static TestLdapPasswordChangeProvider ProviderWithShippedUsernameSettings(
        ShippedUsernameSettings settings, out List<string> filters)
    {
        var options = new LdapPasswordChangeOptions
        {
            // From the shipped file — the values under test.
            DefaultDomain = settings.DefaultDomain,
            LdapSearchFilter = settings.LdapSearchFilter,

            // Deployment-specific; the shipped file leaves these blank on purpose.
            LdapHostnames = new[] { "ldap.example.com" },
            LdapPort = 389,
            LdapUsername = "cn=admin,dc=example,dc=com",
            LdapPassword = "secret",
            LdapSearchBase = "dc=example,dc=com",
        };

        var provider = new TestLdapPasswordChangeProvider(
            NullLogger<LdapPasswordChangeProvider>.Instance,
            Options.Create(options),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>());

        var userEntry = new LdapEntry(
            "cn=jdoe,ou=people,dc=example,dc=com",
            new LdapAttributeSet
            {
                new LdapAttribute("distinguishedName", "cn=jdoe,ou=people,dc=example,dc=com"),
                new LdapAttribute("sAMAccountName", "jdoe"),
                new LdapAttribute("memberOf", "cn=DirectGroup,ou=groups,dc=example,dc=com"),
            });

        var seen = new List<string>();
        filters = seen;

        provider.OnSearchLdap = (filter, _) =>
        {
            seen.Add(filter);

            var results = new Mock<ILdapSearchResults>();
            if (filter == "(sAMAccountName=jdoe)")
            {
                results.Setup(r => r.HasMore()).Returns(true);
                results.Setup(r => r.Next()).Returns(userEntry);
            }
            else
            {
                results.Setup(r => r.HasMore()).Returns(false);
            }

            return results.Object;
        };

        return provider;
    }

    /// <summary>The username-relevant slice of the shipped configuration.</summary>
    private sealed record ShippedUsernameSettings(
        string DefaultDomain,
        string LdapSearchFilter,
        bool UseEmail,
        string UsernameHelpblock);

    private static ShippedUsernameSettings ShippedSettings()
    {
        // The shipped file carries // comments, which the ASP.NET Core JSON
        // configuration provider tolerates and the strict parser does not.
        using var document = JsonDocument.Parse(
            ReadRepoFile(AppSettingsRelativePath),
            new JsonDocumentOptions
            {
                CommentHandling = JsonCommentHandling.Skip,
                AllowTrailingCommas = true,
            });

        var root = document.RootElement;
        var appSettings = Section(root, "AppSettings");
        var clientSettings = Section(root, "ClientSettings");
        var changePasswordForm = Section(clientSettings, "ChangePasswordForm");

        return new ShippedUsernameSettings(
            DefaultDomain: String(appSettings, "DefaultDomain"),
            LdapSearchFilter: String(appSettings, "LdapSearchFilter"),
            // Shipped as the string "true", which the configuration binder parses.
            UseEmail: bool.Parse(String(clientSettings, "UseEmail")),
            UsernameHelpblock: String(changePasswordForm, "UsernameHelpblock"));
    }

    private static JsonElement Section(JsonElement parent, string name)
    {
        Assert.True(
            parent.TryGetProperty(name, out var section),
            $"'{name}' is missing from {AppSettingsRelativePath}.");

        return section;
    }

    private static string String(JsonElement parent, string name) =>
        Section(parent, name).GetString()
        ?? throw new InvalidOperationException($"'{name}' in {AppSettingsRelativePath} is null.");

}
