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
            Ldap(BindLogonFailure, LdapException.InvalidCredentials));

        Assert.IsType<InvalidCredentialsException>(result);
    }

    [Fact]
    public void Translate_ModifyPasswordRestriction_MapsToPolicyViolation()
    {
        var result = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(ModifyPasswordRestriction, LdapException.UnwillingToPerform));

        var policy = Assert.IsType<PasswordPolicyViolationException>(result);
        Assert.Equal(ApiErrorCode.ComplexPassword, policy.ErrorCode);
    }

    [Fact]
    public void Translate_ModifyWrongOldPassword_MapsToInvalidCredentials()
    {
        var result = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(ModifyWrongOldPassword, LdapException.ConstraintViolation));

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

        var result = LdapPasswordChangeProvider.TranslateLdapException(ldapEx);

        var dir = Assert.IsType<DirectoryUnavailableException>(result);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, dir.Message);
        Assert.DoesNotContain(message, dir.Message, StringComparison.Ordinal);
        Assert.Same(ldapEx, dir.InnerException);
    }

    [Fact]
    public void Translate_EmptyServerMessage_MapsToDirectoryUnavailable()
    {
        var result = LdapPasswordChangeProvider.TranslateLdapException(Ldap(string.Empty));

        Assert.IsType<DirectoryUnavailableException>(result);
    }

    [Fact]
    public void Translate_AccountLockedOut_RoutesToInvalidCredentialsUnderConservativePosture()
    {
        // Expectation changed deliberately: account-state codes (locked, disabled,
        // hours, restriction) used to surface as a directory error naming the
        // condition; under the interim conservative posture they are
        // indistinguishable from wrong credentials so the account state leaks
        // to no one. A later phase makes this configurable.
        var result = LdapPasswordChangeProvider.TranslateLdapException(Ldap(
            "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 775, v2580",
            LdapException.InvalidCredentials));

        var cred = Assert.IsType<InvalidCredentialsException>(result);
        Assert.Equal(DirectoryErrorTranslator.InvalidCredentialsMessage, cred.Message);
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
