using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using Xunit;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// What a request costs in service-account binds, and what happens when one cannot
/// be obtained at all.
/// </summary>
/// <remarks>
/// <para>Existing coverage simulates failures through <c>OnSearchLdap</c>, which is a
/// search failing on a connection that is otherwise healthy. Failing to obtain the
/// connection in the first place was unreachable, because the test provider stubbed
/// <c>BindAsServiceAccount</c> to always succeed. That is the gap these close.</para>
/// <para>The bind count matters because it is the property most easily lost to a
/// well-meaning refactor: nothing about a second <c>BindAsServiceAccount()</c> call
/// looks wrong in isolation.</para>
/// </remarks>
public class ServiceAccountConnectionCostTests
{
    private const string UserDn = "cn=testuser,ou=users,dc=example,dc=com";
    private const string RestrictedGroup = "Domain Admins";

    /// <summary>
    /// Resolving the user and writing the new password are both service-account work
    /// against the same directory and share one connection. Two binds here would mean
    /// the change path had gone back to rebinding per operation.
    /// </summary>
    [Fact]
    public async Task APasswordChange_CostsExactlyOneServiceAccountBind()
    {
        var binds = 0;
        var provider = Provider();
        provider.OnBindAsServiceAccount = _ => binds++;
        provider.OnVerifyUserCredentials = (_, _) => { };

        await provider.PerformPasswordChangeAsync("testuser", "current", "new-password");

        Assert.Equal(1, binds);
    }

    /// <summary>
    /// The end-user bind is a separate connection and must stay one: the shared
    /// service-account connection has to keep its identity for the write that
    /// follows, so verification cannot borrow it.
    /// </summary>
    [Fact]
    public async Task CredentialVerification_DoesNotConsumeTheServiceAccountConnection()
    {
        var provider = Provider();
        var bindsBeforeVerification = -1;
        var binds = 0;

        provider.OnBindAsServiceAccount = _ => binds++;
        provider.OnVerifyUserCredentials = (_, _) => bindsBeforeVerification = binds;

        await provider.PerformPasswordChangeAsync("testuser", "current", "new-password");

        // Verification happens after the shared connection is established and before
        // the write, and does not cause another service-account bind of its own.
        Assert.Equal(1, bindsBeforeVerification);
        Assert.Equal(1, binds);
    }

    /// <summary>
    /// A membership question that cannot even open a connection is undetermined, not
    /// "not a member". Answering false here would be the deny-list hole the
    /// undetermined handling exists to close, reached by a different route than a
    /// failing search.
    /// </summary>
    [Fact]
    public async Task AServiceAccountConnectionFailure_IsUndeterminedRatherThanNotAMember()
    {
        var provider = Provider();
        provider.OnBindAsServiceAccount =
            _ => throw new LdapException("cannot reach the directory", LdapException.ConnectError, null);

        // The assertion is that it throws at all: returning false would be the defect.
        await Assert.ThrowsAnyAsync<Exception>(
            () => provider.IsMemberOfGroupAsync("testuser", RestrictedGroup));
    }

    /// <summary>
    /// And the failure is reported as infrastructure, never as the end user's
    /// credentials — the service account's inability to connect says nothing about
    /// the password the caller supplied.
    /// </summary>
    [Fact]
    public async Task AServiceAccountConnectionFailure_IsNotReportedAsInvalidCredentials()
    {
        var provider = Provider();
        provider.OnBindAsServiceAccount =
            _ => throw new LdapException("cannot reach the directory", LdapException.ConnectError, null);

        var thrown = await Assert.ThrowsAnyAsync<Exception>(
            () => provider.IsMemberOfGroupAsync("testuser", RestrictedGroup));

        Assert.IsNotType<InvalidCredentialsException>(thrown);
    }

    private static TestLdapPasswordChangeProvider Provider()
    {
        var options = new LdapPasswordChangeOptions
        {
            LdapHostnames = new[] { "ldap.example.com" },
            LdapPort = 636,
        LdapSecureSocketLayer = true,
            LdapUsername = "cn=admin,dc=example,dc=com",
            LdapPassword = "secret",
            LdapSearchBase = "dc=example,dc=com",
            LdapSearchFilter = "(sAMAccountName={Username})",
            ErrorDisclosureMode = ErrorDisclosureMode.Hardened,
        };

        var provider = new TestLdapPasswordChangeProvider(
            NullLogger<LdapPasswordChangeProvider>.Instance,
            Options.Create(options),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>());

        var userEntry = new LdapEntry(
            UserDn,
            new LdapAttributeSet
            {
                new LdapAttribute("distinguishedName", UserDn),
                new LdapAttribute("sAMAccountName", "testuser"),
            });

        provider.OnSearchLdap = (filter, _) =>
            filter.Contains("sAMAccountName=", StringComparison.Ordinal)
                ? Results(userEntry)
                : Results();

        return provider;
    }

    private static ILdapSearchResults Results(params LdapEntry[] entries)
    {
        var mock = new Mock<ILdapSearchResults>();
        var remaining = new Queue<LdapEntry>(entries);

        mock.Setup(r => r.HasMoreAsync(It.IsAny<System.Threading.CancellationToken>())).ReturnsAsync(() => remaining.Count > 0);
        mock.Setup(r => r.NextAsync(It.IsAny<System.Threading.CancellationToken>())).ReturnsAsync(() => remaining.Dequeue());
        return mock.Object;
    }
}
