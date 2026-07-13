using Novell.Directory.Ldap;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

public class LdapExceptionTranslationTests
{
    // Realistic AD extended error messages. Bind failures lead with a generic
    // SEC_E code and carry the Win32 code in the "data" field; operation
    // (modify/search) failures lead with the Win32 code itself.
    private const string BindLogonFailure =
        "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 52e, v2580";

    private const string BindPasswordExpired =
        "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 532, v2580";

    private const string BindPasswordMustChange =
        "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 773, v2580";

    private const string ModifyPasswordRestriction =
        "0000052D: SvcErr: DSID-031A12D2, problem 5003 (WILL_NOT_PERFORM), data 0";

    private const string ModifyWrongOldPassword =
        "00000056: AtrErr: DSID-03191083, #1:\n\t0: 00000056: DSID-03191083, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 9005a (unicodePwd)";

    private static LdapException Ldap(string serverMessage, int resultCode = LdapException.Other) =>
        new("test", resultCode, serverMessage);

    [Fact]
    public void Translate_BindStyleLogonFailure_MapsToInvalidCredentials()
    {
        var result = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(BindLogonFailure, LdapException.InvalidCredentials),
            ErrorDisclosureMode.Hardened);

        Assert.IsType<InvalidCredentialsException>(result);
    }

    [Fact]
    public void Translate_ModifyPasswordRestriction_MapsToPolicyViolation()
    {
        var result = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(ModifyPasswordRestriction, LdapException.UnwillingToPerform),
            ErrorDisclosureMode.Hardened);

        var policy = Assert.IsType<PasswordPolicyViolationException>(result);
        Assert.Equal(ApiErrorCode.ComplexPassword, policy.ErrorCode);
    }

    [Fact]
    public void Translate_ModifyWrongOldPassword_MapsToInvalidCredentials()
    {
        var result = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(ModifyWrongOldPassword, LdapException.ConstraintViolation),
            ErrorDisclosureMode.Hardened);

        Assert.IsType<InvalidCredentialsException>(result);
    }

    [Fact]
    public void Translate_UnknownCode_UsesCuratedMessageAndKeepsServerTextForLogsOnly()
    {
        // Expectation changed deliberately: the server's diagnostic string used to
        // be surfaced verbatim as the wire message; it now survives only in the
        // inner exception (for logs) while the wire carries a curated constant.
        const string message = "some vendor-specific failure without codes";
        var ldapEx = Ldap(message);

        var result = LdapPasswordChangeProvider.TranslateLdapException(ldapEx, ErrorDisclosureMode.Hardened);

        var dir = Assert.IsType<DirectoryUnavailableException>(result);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, dir.Message);
        Assert.DoesNotContain(message, dir.Message, StringComparison.Ordinal);
        Assert.Same(ldapEx, dir.InnerException);
    }

    [Fact]
    public void Translate_EmptyServerMessage_MapsToDirectoryUnavailable()
    {
        var result = LdapPasswordChangeProvider.TranslateLdapException(Ldap(string.Empty), ErrorDisclosureMode.Hardened);

        Assert.IsType<DirectoryUnavailableException>(result);
    }

    private const string BindAccountLockedOut =
        "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 775, v2580";

    private const string BindNoSuchUser =
        "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 525, v2580";

    [Fact]
    public void Translate_AccountLockedOut_Hardened_IsIndistinguishableFromWrongCredentials()
    {
        var result = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(BindAccountLockedOut, LdapException.InvalidCredentials),
            ErrorDisclosureMode.Hardened);

        var cred = Assert.IsType<InvalidCredentialsException>(result);
        Assert.Equal(DirectoryErrorTranslator.InvalidCredentialsMessage, cred.Message);
    }

    [Fact]
    public void Translate_AccountLockedOut_Informative_ReportsChangeNotPermitted()
    {
        var result = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(BindAccountLockedOut, LdapException.InvalidCredentials),
            ErrorDisclosureMode.Informative);

        var policy = Assert.IsType<PasswordPolicyViolationException>(result);
        Assert.Equal(ApiErrorCode.ChangeNotPermitted, policy.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.AccountStateMessage, policy.Message);
    }

    [Fact]
    public void Translate_NoSuchUser_Informative_ReportsUserNotFound()
    {
        var result = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(BindNoSuchUser, LdapException.InvalidCredentials),
            ErrorDisclosureMode.Informative);

        var notFound = Assert.IsType<UserNotFoundException>(result);
        Assert.Equal(DirectoryErrorTranslator.UserNotFoundMessage, notFound.Message);
    }

    [Fact]
    public void ExtractWin32ErrorCode_BindStyle_PrefersDataSubCodeOverSecECode()
    {
        // The leading 80090308 is a generic SSPI code; the diagnostic is data 52e.
        var code = LdapPasswordChangeProvider.ExtractWin32ErrorCode(BindLogonFailure);

        Assert.NotNull(code);
        Assert.Equal(0x52E, code.Code);
    }

    [Fact]
    public void ExtractWin32ErrorCode_ModifyStyle_UsesLeadingCodeAndIgnoresDataZero()
    {
        var code = LdapPasswordChangeProvider.ExtractWin32ErrorCode(ModifyPasswordRestriction);

        Assert.NotNull(code);
        Assert.Equal(0x52D, code.Code);
    }

    [Fact]
    public void ExtractWin32ErrorCode_NoRecognizableCode_ReturnsNull()
    {
        Assert.Null(LdapPasswordChangeProvider.ExtractWin32ErrorCode(
            "Connection reset by peer"));
    }

    [Theory]
    [InlineData(BindPasswordExpired)]
    [InlineData(BindPasswordMustChange)]
    public void IsPasswordExpiredOrMustChange_AdExpiredOrMustChangeBind_ReturnsTrue(string serverMessage)
    {
        var ex = Ldap(serverMessage, LdapException.InvalidCredentials);

        Assert.True(LdapPasswordChangeProvider.IsPasswordExpiredOrMustChange(ex));
    }

    [Fact]
    public void IsPasswordExpiredOrMustChange_PlainLogonFailure_ReturnsFalse()
    {
        var ex = Ldap(BindLogonFailure, LdapException.InvalidCredentials);

        Assert.False(LdapPasswordChangeProvider.IsPasswordExpiredOrMustChange(ex));
    }

    [Fact]
    public void IsPasswordExpiredOrMustChange_NonInvalidCredentialsResultCode_ReturnsFalse()
    {
        // Same message, but a result code other than 49 must not be trusted.
        var ex = Ldap(BindPasswordExpired, LdapException.UnwillingToPerform);

        Assert.False(LdapPasswordChangeProvider.IsPasswordExpiredOrMustChange(ex));
    }

    [Fact]
    public void IsPasswordExpiredOrMustChange_GenericServerWithoutDataField_ReturnsFalse()
    {
        var ex = Ldap("Invalid credentials", LdapException.InvalidCredentials);

        Assert.False(LdapPasswordChangeProvider.IsPasswordExpiredOrMustChange(ex));
    }
}
