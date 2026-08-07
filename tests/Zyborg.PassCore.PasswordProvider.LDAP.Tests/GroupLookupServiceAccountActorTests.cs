using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;
using System;
using System.Threading.Tasks;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Models;
using Xunit;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// Every directory operation reachable from the group-membership lookup runs on
/// the <b>service account's</b> connection, so a failure there describes the
/// application's own configuration and must never be reported to the caller as
/// their credentials being wrong.
/// </summary>
/// <remarks>
/// <para>The lookup's <c>catch (LdapException)</c> previously translated with the
/// default <see cref="DirectoryActor.User"/>. Active Directory reports search
/// failures in the same extended-error shape it uses for bind failures, so a
/// service-account search rejected with <c>data 52e</c>
/// (<c>ERROR_LOGON_FAILURE</c>) was classified as
/// <see cref="DirectoryFailureClass.Credentials"/> and surfaced to the end user
/// as <see cref="ApiErrorCode.InvalidCredentials"/> — telling them their password
/// was wrong when the real fault was the service account's.</para>
/// <para>This is the invariant <see cref="DirectoryActor"/> exists to enforce, and
/// the "undetermined" branch a few lines above the catch already applied it. These
/// tests pin the catch to the same actor, so the two cannot drift apart again.</para>
/// <para>Both disclosure modes are covered because the collapse happens in
/// <see cref="DirectoryErrorTranslator.ClassifyForActor"/>, before the mode is
/// consulted: a service-account failure is infrastructure in <em>both</em> modes,
/// and a mode-dependent result here would mean the actor was not applied.</para>
/// </remarks>
public class GroupLookupServiceAccountActorTests
{
    /// <summary>
    /// An AD extended error carrying the Win32 code in the <c>data</c> field, the
    /// shape a rejected bind-or-search reports. <c>52e</c> is
    /// <c>ERROR_LOGON_FAILURE</c>, which classifies as
    /// <see cref="DirectoryFailureClass.Credentials"/> under
    /// <see cref="DirectoryActor.User"/>.
    /// </summary>
    private const string LogonFailureExtendedError =
        "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 52e, v2580";

    private static LdapPasswordChangeOptions CreateOptions(ErrorDisclosureMode mode) => new()
    {
        LdapHostnames = new[] { "ldap.example.com" },
        LdapPort = 389,
        LdapUsername = "cn=admin,dc=example,dc=com",
        LdapPassword = "secret",
        LdapSearchBase = "dc=example,dc=com",
        LdapSearchFilter = "(sAMAccountName={Username})",
        ErrorDisclosureMode = mode,
    };

    private static TestLdapPasswordChangeProvider Provider(ErrorDisclosureMode mode)
    {
        var provider = new TestLdapPasswordChangeProvider(
            NullLogger<LdapPasswordChangeProvider>.Instance,
            Options.Create(CreateOptions(mode)),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>());

        // The service account's own search is rejected. This is the application's
        // failure, not the caller's -- the caller has supplied only a username at
        // this point and has proved nothing.
        provider.OnSearchLdap = (_, _) => throw new LdapException(
            "search rejected", LdapException.InvalidCredentials, LogonFailureExtendedError);

        return provider;
    }

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public async Task ServiceAccountSearchFailure_IsNotReportedAsInvalidCredentials(ErrorDisclosureMode mode)
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(
            () => Provider(mode).IsMemberOfGroupAsync("testuser", "SomeGroup"));

        var wire = ApiErrorMapper.Map(error);

        // The regression guard: 0x52E under DirectoryActor.User would be
        // InvalidCredentials (4) with "Invalid username or password".
        Assert.NotEqual(ApiErrorCode.InvalidCredentials, wire.ErrorCode);
        Assert.NotEqual(DirectoryErrorTranslator.InvalidCredentialsMessage, wire.Message);

        Assert.Equal(ApiErrorCode.LdapProblem, wire.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, wire.Message);
    }

    /// <summary>
    /// The curated wire message must not carry the server's diagnostic text, in
    /// either mode — the operator gets that from the log, the caller never does.
    /// </summary>
    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public async Task ServiceAccountSearchFailure_LeaksNoServerDiagnosticText(ErrorDisclosureMode mode)
    {
        var error = await Assert.ThrowsAnyAsync<Exception>(
            () => Provider(mode).IsMemberOfGroupAsync("testuser", "SomeGroup"));

        var message = ApiErrorMapper.Map(error).Message;

        Assert.DoesNotContain("DSID", message, StringComparison.Ordinal);
        Assert.DoesNotContain("data 52e", message, StringComparison.Ordinal);
        Assert.DoesNotContain("AcceptSecurityContext", message, StringComparison.Ordinal);
    }
}
