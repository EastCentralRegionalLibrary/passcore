using System;
using System.Collections.Generic;
using System.Net.Sockets;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// Exposes the protected seam <see cref="LdapPasswordChangeProvider"/> actually
/// ships — <c>TryGetTransportWin32Code</c> and the inherited
/// <c>TranslateDirectoryException</c> — so the real override can be exercised
/// directly rather than only through the static
/// <see cref="LdapPasswordChangeProvider.TranslateLdapException(LdapException, ErrorDisclosureMode)"/>
/// helper the rest of this project relies on. Mirrors the subclassing pattern
/// established by <c>TestLdapPasswordChangeProvider</c> in
/// <c>GroupMembershipParityTests.cs</c>.
/// </summary>
internal sealed class ExposedLdapPasswordChangeProvider : LdapPasswordChangeProvider
{
    public ExposedLdapPasswordChangeProvider(LdapPasswordChangeOptions options)
        : base(
            NullLogger<LdapPasswordChangeProvider>.Instance,
            Options.Create(options),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>())
    {
    }

    public bool TestTryGetTransportWin32Code(Exception exception, out int win32Code) =>
        TryGetTransportWin32Code(exception, out win32Code);

    public Exception TestTranslateDirectoryException(
        Exception exception, DirectoryActor actor, out DirectoryFailureClass failureClass) =>
        TranslateDirectoryException(exception, actor, out failureClass);
}

/// <summary>
/// Covers the production override
/// <see cref="LdapPasswordChangeProvider.TryGetTransportWin32Code"/> and, through
/// it, the instance-seam <c>TranslateDirectoryException</c> the shipping
/// provider actually calls (unlike <see cref="LdapExceptionTranslationTests"/>,
/// which exercises only the static <c>TranslateLdapException</c> helper).
/// </summary>
public class LdapTransportWin32CodeRecoveryTests
{
    private const string BindLogonFailure =
        "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 52e, v2580";

    private const string BindOtherLogonFailure =
        "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 525, v2580";

    private static LdapPasswordChangeOptions CreateOptions() => new()
    {
        LdapHostnames = new[] { "ldap.example.com" },
        LdapPort = 636,
        LdapSecureSocketLayer = true,
        LdapUsername = "cn=admin,dc=example,dc=com",
        LdapPassword = "secret",
        LdapSearchBase = "dc=example,dc=com",
        LdapSearchFilter = "(sAMAccountName={Username})",
    };

    private static ExposedLdapPasswordChangeProvider CreateProvider() =>
        new(CreateOptions());

    private static LdapException Ldap(string serverMessage, int resultCode = LdapException.InvalidCredentials) =>
        new("test", resultCode, serverMessage);

    // (a) A parseable AD extended-error message yields the recovered code.
    [Fact]
    public void TryGetTransportWin32Code_LdapExceptionWithParseableMessage_RecoversCode()
    {
        var provider = CreateProvider();
        var ex = Ldap(BindLogonFailure);

        var found = provider.TestTryGetTransportWin32Code(ex, out var code);

        Assert.True(found);
        Assert.Equal(0x52E, code);
    }

    // (b) An outer exception wrapping a parseable LdapException still resolves
    // via the chain walk.
    [Fact]
    public void TryGetTransportWin32Code_LdapExceptionWrappedByOuterException_StillRecoversCode()
    {
        var provider = CreateProvider();
        var ldapEx = Ldap(BindLogonFailure);
        var wrapper = new InvalidOperationException("wrapped", ldapEx);

        var found = provider.TestTryGetTransportWin32Code(wrapper, out var code);

        Assert.True(found);
        Assert.Equal(0x52E, code);
    }

    // (c) An LdapException with a null/whitespace LdapErrorMessage whose inner
    // exception is a SocketException must NOT recover a code from the socket
    // error number — pinning the removal of the base fallback (Fix 1) — and
    // must therefore route to DirectoryUnavailableException.
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TryGetTransportWin32Code_LdapExceptionWithNoParseableMessage_DoesNotFallBackToSocketErrorNumber(
        string? serverMessage)
    {
        var provider = CreateProvider();
        var socketEx = new SocketException((int)SocketError.ConnectionRefused);
        var ex = new LdapException("connect failed", LdapException.Other, serverMessage, socketEx);

        var found = provider.TestTryGetTransportWin32Code(ex, out var code);

        Assert.False(found);
        Assert.Equal(0, code);
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void TranslateDirectoryException_LdapExceptionWithNoParseableMessageAndSocketInner_RoutesToDirectoryUnavailable(
        string? serverMessage)
    {
        var provider = CreateProvider();
        var socketEx = new SocketException((int)SocketError.ConnectionRefused);
        var ex = new LdapException("connect failed", LdapException.Other, serverMessage, socketEx);

        var translated = provider.TestTranslateDirectoryException(ex, DirectoryActor.User, out var failureClass);

        var unavailable = Assert.IsType<DirectoryUnavailableException>(translated);
        Assert.Equal(DirectoryFailureClass.Infrastructure, failureClass);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, unavailable.Message);
        Assert.Same(ex, unavailable.InnerException);
    }

    // (d) Outermost-wins ordering when two LdapExceptions in one chain carry
    // different codes.
    [Fact]
    public void TryGetTransportWin32Code_TwoLdapExceptionsInChain_OutermostWins()
    {
        var provider = CreateProvider();
        var innerLdapEx = Ldap(BindOtherLogonFailure); // 0x525
        var outerLdapEx = new LdapException(
            "outer", LdapException.InvalidCredentials, BindLogonFailure, innerLdapEx); // 0x52E

        var found = provider.TestTryGetTransportWin32Code(outerLdapEx, out var code);

        Assert.True(found);
        Assert.Equal(0x52E, code);
    }

    // (e) ServiceAccount-actor translation through the instance seam: a
    // credentials-class code (0x52E) must still collapse to infrastructure on
    // the shipping path, not just through the static helper.
    [Fact]
    public void TranslateDirectoryException_ServiceAccountActor_CollapsesCredentialsCodeToInfrastructure()
    {
        var provider = CreateProvider();
        var ex = Ldap(BindLogonFailure);

        var translated = provider.TestTranslateDirectoryException(
            ex, DirectoryActor.ServiceAccount, out var failureClass);

        Assert.IsType<DirectoryUnavailableException>(translated);
        Assert.Equal(DirectoryFailureClass.Infrastructure, failureClass);
    }

    [Fact]
    public void TranslateDirectoryException_UserActor_CredentialsCodeStaysInvalidCredentials()
    {
        var provider = CreateProvider();
        var ex = Ldap(BindLogonFailure);

        var translated = provider.TestTranslateDirectoryException(
            ex, DirectoryActor.User, out var failureClass);

        Assert.IsType<InvalidCredentialsException>(translated);
        Assert.Equal(DirectoryFailureClass.Credentials, failureClass);
    }
}
