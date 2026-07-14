using Novell.Directory.Ldap;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// Exercises the exact decision code the LDAP provider runs when a delete/add
/// password change fails: translation of the failure plus the shared
/// administrative-reset gate. These are the provider-level guarantees for
/// <c>AllowAdministrativeReset</c> without a live directory.
/// </summary>
public class LdapAdministrativeResetTests
{
    // AD's modify-time policy rejection (history/minimum-age/complexity all
    // surface as WILL_NOT_PERFORM with leading 52D).
    private const string PolicyRejection =
        "0000052D: SvcErr: DSID-031A12D2, problem 5003 (WILL_NOT_PERFORM), data 0";

    // AD's modify-time wrong-old-password rejection for delete/add.
    private const string WrongOldPassword =
        "00000056: AtrErr: DSID-03191083, #1:\n\t0: 00000056: DSID-03191083, problem 1005 (CONSTRAINT_ATT_TYPE), data 0, Att 9005a (unicodePwd)";

    private static LdapException Ldap(string serverMessage) =>
        new("test", LdapException.UnwillingToPerform, serverMessage);

    private static LdapPasswordChangeOptions Options(
        bool allowReset,
        bool delAdd = true) => new()
    {
        AllowAdministrativeReset = allowReset,
        LdapChangePasswordWithDelAdd = delAdd,
        ErrorDisclosureMode = ErrorDisclosureMode.Hardened,
    };

    [Fact]
    public void OptionOff_PolicyRejection_SurfacesAsComplexPassword_NoResetAttempt()
    {
        // The default-off contract: a history/policy rejection is reported to
        // the user as ComplexPassword — never rescued, never Generic.
        var translated = LdapPasswordChangeProvider.TranslateAndDecideRescue(
            Ldap(PolicyRejection),
            Options(allowReset: false),
            currentPasswordVerified: true,
            out var attemptReset);

        Assert.False(attemptReset);
        var policy = Assert.IsType<PasswordPolicyViolationException>(translated);
        Assert.Equal(ApiErrorCode.ComplexPassword, policy.ErrorCode);

        var item = ApiErrorMapper.Map(translated);
        Assert.Equal(ApiErrorCode.ComplexPassword, item.ErrorCode);
        Assert.NotEqual(ApiErrorCode.Generic, item.ErrorCode);
    }

    [Fact]
    public void OptionOn_VerifiedPolicyRejection_AttemptsReset()
    {
        var translated = LdapPasswordChangeProvider.TranslateAndDecideRescue(
            Ldap(PolicyRejection),
            Options(allowReset: true),
            currentPasswordVerified: true,
            out var attemptReset);

        Assert.True(attemptReset);
        Assert.IsType<PasswordPolicyViolationException>(translated);
    }

    [Fact]
    public void OptionOn_WithoutVerifiedCredentials_NeverAttemptsReset()
    {
        // The account-takeover invariant at the provider level: even with the
        // option enabled and a rescuable failure, no verification means no reset.
        _ = LdapPasswordChangeProvider.TranslateAndDecideRescue(
            Ldap(PolicyRejection),
            Options(allowReset: true),
            currentPasswordVerified: false,
            out var attemptReset);

        Assert.False(attemptReset);
    }

    [Fact]
    public void OptionOn_WrongOldPasswordAtModifyTime_NeverAttemptsReset()
    {
        // A credentials-class failure is not rescuable: resetting over it would
        // change the password of an account whose old password just failed.
        var translated = LdapPasswordChangeProvider.TranslateAndDecideRescue(
            Ldap(WrongOldPassword),
            Options(allowReset: true),
            currentPasswordVerified: true,
            out var attemptReset);

        Assert.False(attemptReset);
        Assert.IsType<InvalidCredentialsException>(translated);
    }

    [Fact]
    public void OptionOn_InfrastructureFailure_NeverAttemptsReset()
    {
        var translated = LdapPasswordChangeProvider.TranslateAndDecideRescue(
            Ldap("vendor-specific failure without codes"),
            Options(allowReset: true),
            currentPasswordVerified: true,
            out var attemptReset);

        Assert.False(attemptReset);
        Assert.IsType<DirectoryUnavailableException>(translated);
    }

    [Fact]
    public void OptionOn_ReplaceMechanism_NeverAttemptsReset()
    {
        // With LdapChangePasswordWithDelAdd=false the primary operation is
        // already an administrative replace; the fallback adds nothing.
        _ = LdapPasswordChangeProvider.TranslateAndDecideRescue(
            Ldap(PolicyRejection),
            Options(allowReset: true, delAdd: false),
            currentPasswordVerified: true,
            out var attemptReset);

        Assert.False(attemptReset);
    }

    [Fact]
    public void Defaults_AllowAdministrativeResetIsOff()
    {
        Assert.False(new LdapPasswordChangeOptions().AllowAdministrativeReset);
    }
}
