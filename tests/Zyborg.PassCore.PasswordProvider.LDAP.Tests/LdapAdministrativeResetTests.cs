using Novell.Directory.Ldap;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// Exercises the exact decision code the LDAP provider runs when a delete/add
/// password change fails or a cannot-change flag is detected: translation of
/// the failure plus the shared administrative-reset gate. These are the
/// provider-level guarantees for <c>AllowAdministrativeReset</c> without a
/// live directory.
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

    // A cannot-change condition reported as an error code (NERR_PasswordCantChange).
    private const string CannotChangeRejection =
        "000008C3: SvcErr: DSID-031A12D2, problem 5003 (WILL_NOT_PERFORM), data 0";

    private static LdapException Ldap(string serverMessage) =>
        new("test", LdapException.UnwillingToPerform, serverMessage);

    private static LdapPasswordChangeOptions Options(
        bool allowReset,
        bool delAdd = true,
        ErrorDisclosureMode mode = ErrorDisclosureMode.Hardened) => new()
    {
        AllowAdministrativeReset = allowReset,
        LdapChangePasswordWithDelAdd = delAdd,
        ErrorDisclosureMode = mode,
    };

    [Fact]
    public void OptionOff_CannotChange_SurfacesAsCuratedChangeNotPermitted_NoResetAttempt()
    {
        var translated = LdapPasswordChangeProvider.TranslateAndDecideRescue(
            Ldap(CannotChangeRejection),
            Options(allowReset: false),
            currentPasswordVerified: true,
            out var attemptReset);

        Assert.False(attemptReset);
        var policy = Assert.IsType<PasswordPolicyViolationException>(translated);
        Assert.Equal(ApiErrorCode.ChangeNotPermitted, policy.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.ChangeNotPermittedMessage, policy.Message);
    }

    [Fact]
    public void OptionOn_VerifiedCannotChange_AttemptsReset()
    {
        // The feature's one rescuable condition.
        var translated = LdapPasswordChangeProvider.TranslateAndDecideRescue(
            Ldap(CannotChangeRejection),
            Options(allowReset: true),
            currentPasswordVerified: true,
            out var attemptReset);

        Assert.True(attemptReset);
        Assert.IsType<PasswordPolicyViolationException>(translated);
    }

    [Fact]
    public void OptionOn_PolicyRejection_IsNeverRescued_PolicyIsHonored()
    {
        // Expectation reversed deliberately from the first Phase 3 revision:
        // the original gate rescued policy rejections (history/minimum-age),
        // which bypasses intentional domain policy. Policy rejections now
        // always surface as ComplexPassword — never Generic, never rescued.
        var translated = LdapPasswordChangeProvider.TranslateAndDecideRescue(
            Ldap(PolicyRejection),
            Options(allowReset: true),
            currentPasswordVerified: true,
            out var attemptReset);

        Assert.False(attemptReset);
        var policy = Assert.IsType<PasswordPolicyViolationException>(translated);
        Assert.Equal(ApiErrorCode.ComplexPassword, policy.ErrorCode);

        var item = ApiErrorMapper.Map(translated);
        Assert.Equal(ApiErrorCode.ComplexPassword, item.ErrorCode);
        Assert.NotEqual(ApiErrorCode.Generic, item.ErrorCode);
    }

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public void OptionOn_AccountStateFailure_IsNeverRescuedInEitherMode(ErrorDisclosureMode mode)
    {
        // Locked-out at modify time. In informative mode this renders with the
        // same exception type and ApiErrorCode as cannot-change — the gate must
        // distinguish them by class, not shape.
        var lockedOut = new LdapException("test", LdapException.InvalidCredentials,
            "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 775, v2580");

        _ = LdapPasswordChangeProvider.TranslateAndDecideRescue(
            lockedOut,
            Options(allowReset: true, mode: mode),
            currentPasswordVerified: true,
            out var attemptReset);

        Assert.False(attemptReset);
    }

    [Fact]
    public void OptionOn_WithoutVerifiedCredentials_NeverAttemptsReset()
    {
        // The account-takeover invariant at the provider level: even with the
        // option enabled and the rescuable condition, no verification means no reset.
        _ = LdapPasswordChangeProvider.TranslateAndDecideRescue(
            Ldap(CannotChangeRejection),
            Options(allowReset: true),
            currentPasswordVerified: false,
            out var attemptReset);

        Assert.False(attemptReset);
    }

    [Fact]
    public void OptionOn_WrongOldPasswordAtModifyTime_NeverAttemptsReset()
    {
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
            Ldap(CannotChangeRejection),
            Options(allowReset: true, delAdd: false),
            currentPasswordVerified: true,
            out var attemptReset);

        Assert.False(attemptReset);
    }

    [Theory]
    [InlineData(CannotChangeRejection, DirectoryFailureClass.ChangeNotPermitted)]
    [InlineData(PolicyRejection, DirectoryFailureClass.NewPasswordPolicy)]
    [InlineData(WrongOldPassword, DirectoryFailureClass.Credentials)]
    [InlineData("no codes at all", DirectoryFailureClass.Infrastructure)]
    public void TranslateAndDecideRescue_AgreesWithShouldRescue_SingleDecisionPoint(
        string serverMessage, DirectoryFailureClass expectedClass)
    {
        // Decision-point unification: the modify-failure path
        // (TranslateAndDecideRescue) and the pre-flight path (which calls
        // ShouldRescue with a synthesized class) must route through the same
        // seam, so eligibility cannot drift between the two call sites.
        foreach (var allowReset in new[] { true, false })
        {
            foreach (var verified in new[] { true, false })
            {
                var options = Options(allowReset);

                _ = LdapPasswordChangeProvider.TranslateAndDecideRescue(
                    Ldap(serverMessage), options, verified, out var fromCatchPath);

                var fromSeam = LdapPasswordChangeProvider.ShouldRescue(options, verified, expectedClass);

                Assert.Equal(fromSeam, fromCatchPath);
            }
        }
    }

    [Fact]
    public void ShouldRescue_SynthesizedChangeNotPermitted_MatchesGateSemantics()
    {
        // The pre-flight (detected flag) entry point.
        Assert.True(LdapPasswordChangeProvider.ShouldRescue(
            Options(allowReset: true), currentPasswordVerified: true, DirectoryFailureClass.ChangeNotPermitted));
        Assert.False(LdapPasswordChangeProvider.ShouldRescue(
            Options(allowReset: false), currentPasswordVerified: true, DirectoryFailureClass.ChangeNotPermitted));
        Assert.False(LdapPasswordChangeProvider.ShouldRescue(
            Options(allowReset: true), currentPasswordVerified: false, DirectoryFailureClass.ChangeNotPermitted));
        Assert.False(LdapPasswordChangeProvider.ShouldRescue(
            Options(allowReset: true, delAdd: false), currentPasswordVerified: true, DirectoryFailureClass.ChangeNotPermitted));
    }

    [Fact]
    public void Defaults_AllowAdministrativeResetIsOff()
    {
        Assert.False(new LdapPasswordChangeOptions().AllowAdministrativeReset);
    }
}
