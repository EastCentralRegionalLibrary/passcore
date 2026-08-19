using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Novell.Directory.Ldap;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// Exercises the shipping decision seam the LDAP provider actually runs when a
/// delete/add password change fails or a cannot-change flag is detected: the
/// provider's own <c>AdministrativeResetSupported</c> override, translation
/// via <see cref="LdapPasswordChangeProvider.TranslateLdapException(LdapException, ErrorDisclosureMode, out DirectoryFailureClass)"/>,
/// and the shared <see cref="AdministrativeReset.ShouldAttempt"/> gate.
///
/// <para><b>Why this no longer drives <c>ShouldRescue</c>/<c>TranslateAndDecideRescue</c>.</b>
/// Those two static helpers duplicated the eligibility rule that now ships in
/// <see cref="Unosquare.PassCore.Common.DirectoryPasswordChangeProviderBase.PerformGatedPasswordWrite"/> —
/// exactly the kind of drift that let the Active Directory provider's own
/// <c>AdministrativeResetSupported</c> override go missing for a full round
/// without any test noticing. They had zero production callers (only each
/// other, and these tests) and have been deleted rather than kept as a second,
/// unreachable copy of the rule. Testing the shipping seam directly — a real
/// <see cref="LdapPasswordChangeProvider"/> instance's <c>AdministrativeResetSupported</c>
/// plus <see cref="AdministrativeReset.ShouldAttempt"/> — means a future
/// consolidation that silently drops either one is caught here rather than by
/// a test that never runs the real code.</para>
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
        LdapHostnames = new[] { "ldap.example.com" },
        LdapUsername = "cn=admin,dc=example,dc=com",
        LdapPassword = "secret",
        LdapSearchBase = "dc=example,dc=com",
        LdapPort = 636,
        LdapSecureSocketLayer = true,
        LdapSearchFilter = "(sAMAccountName={Username})",
        AllowAdministrativeReset = allowReset,
        LdapChangePasswordWithDelAdd = delAdd,
        ErrorDisclosureMode = mode,
    };

    /// <summary>
    /// Exposes the protected <c>AdministrativeResetSupported</c> override
    /// through a real, constructible provider instance — the shipping seam
    /// itself, not a stand-in for it.
    /// </summary>
    private sealed class ExposedProvider : LdapPasswordChangeProvider
    {
        public ExposedProvider(LdapPasswordChangeOptions options)
            : base(
                NullLogger<LdapPasswordChangeProvider>.Instance,
                Microsoft.Extensions.Options.Options.Create(options),
                Microsoft.Extensions.Options.Options.Create(new ClientSettings()),
                Array.Empty<IPasswordPolicy>())
        {
        }

        public bool ExposedAdministrativeResetSupported => AdministrativeResetSupported;
    }

    private static bool SupportedFor(bool delAdd) =>
        new ExposedProvider(Options(allowReset: true, delAdd: delAdd)).ExposedAdministrativeResetSupported;

    private static bool IsRescueEligible(
        bool delAdd, bool allowReset, bool currentPasswordVerified, DirectoryFailureClass failureClass) =>
        SupportedFor(delAdd)
        && AdministrativeReset.ShouldAttempt(allowReset, currentPasswordVerified, failureClass);

    [Fact]
    public void OptionOff_CannotChange_SurfacesAsCuratedChangeNotPermitted_NoResetAttempt()
    {
        var translated = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(CannotChangeRejection), ErrorDisclosureMode.Hardened, out var failureClass);

        var attemptReset = IsRescueEligible(
            delAdd: true, allowReset: false, currentPasswordVerified: true, failureClass);

        Assert.False(attemptReset);
        var policy = Assert.IsType<PasswordPolicyViolationException>(translated);
        Assert.Equal(ApiErrorCode.ChangeNotPermitted, policy.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.ChangeNotPermittedMessage, policy.Message);
    }

    [Fact]
    public void OptionOn_VerifiedCannotChange_AttemptsReset()
    {
        // The feature's one rescuable condition.
        var translated = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(CannotChangeRejection), ErrorDisclosureMode.Hardened, out var failureClass);

        var attemptReset = IsRescueEligible(
            delAdd: true, allowReset: true, currentPasswordVerified: true, failureClass);

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
        var translated = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(PolicyRejection), ErrorDisclosureMode.Hardened, out var failureClass);

        var attemptReset = IsRescueEligible(
            delAdd: true, allowReset: true, currentPasswordVerified: true, failureClass);

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
        LdapPasswordChangeProvider.TranslateLdapException(
            new LdapException("test", LdapException.InvalidCredentials,
                "80090308: LdapErr: DSID-0C0903A9, comment: AcceptSecurityContext error, data 775, v2580"),
            mode,
            out var failureClass);

        var attemptReset = IsRescueEligible(
            delAdd: true, allowReset: true, currentPasswordVerified: true, failureClass);

        Assert.False(attemptReset);
    }

    [Fact]
    public void OptionOn_WithoutVerifiedCredentials_NeverAttemptsReset()
    {
        // The account-takeover invariant at the provider level: even with the
        // option enabled and the rescuable condition, no verification means no reset.
        LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(CannotChangeRejection), ErrorDisclosureMode.Hardened, out var failureClass);

        var attemptReset = IsRescueEligible(
            delAdd: true, allowReset: true, currentPasswordVerified: false, failureClass);

        Assert.False(attemptReset);
    }

    [Fact]
    public void OptionOn_WrongOldPasswordAtModifyTime_NeverAttemptsReset()
    {
        var translated = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(WrongOldPassword), ErrorDisclosureMode.Hardened, out var failureClass);

        var attemptReset = IsRescueEligible(
            delAdd: true, allowReset: true, currentPasswordVerified: true, failureClass);

        Assert.False(attemptReset);
        Assert.IsType<InvalidCredentialsException>(translated);
    }

    [Fact]
    public void OptionOn_InfrastructureFailure_NeverAttemptsReset()
    {
        var translated = LdapPasswordChangeProvider.TranslateLdapException(
            Ldap("vendor-specific failure without codes"), ErrorDisclosureMode.Hardened, out var failureClass);

        var attemptReset = IsRescueEligible(
            delAdd: true, allowReset: true, currentPasswordVerified: true, failureClass);

        Assert.False(attemptReset);
        Assert.IsType<DirectoryUnavailableException>(translated);
    }

    [Fact]
    public void OptionOn_ReplaceMechanism_NeverAttemptsReset()
    {
        // With LdapChangePasswordWithDelAdd=false the primary operation is
        // already an administrative replace; the fallback adds nothing.
        LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(CannotChangeRejection), ErrorDisclosureMode.Hardened, out var failureClass);

        var attemptReset = IsRescueEligible(
            delAdd: false, allowReset: true, currentPasswordVerified: true, failureClass);

        Assert.False(attemptReset);
    }

    [Theory]
    [InlineData(CannotChangeRejection, DirectoryFailureClass.ChangeNotPermitted)]
    [InlineData(PolicyRejection, DirectoryFailureClass.NewPasswordPolicy)]
    [InlineData(WrongOldPassword, DirectoryFailureClass.Credentials)]
    [InlineData("no codes at all", DirectoryFailureClass.Infrastructure)]
    public void TranslatedFailureClass_AgreesWithGateAcrossOptionCombinations(
        string serverMessage, DirectoryFailureClass expectedClass)
    {
        // Decision-point unification: the modify-failure translation path and
        // the pre-flight path (which synthesizes ChangeNotPermitted directly)
        // must route through the same AdministrativeResetSupported/ShouldAttempt
        // seam, so eligibility cannot drift between the two call sites.
        LdapPasswordChangeProvider.TranslateLdapException(
            Ldap(serverMessage), ErrorDisclosureMode.Hardened, out var fromCatchPath);

        Assert.Equal(expectedClass, fromCatchPath);

        foreach (var allowReset in new[] { true, false })
        {
            foreach (var verified in new[] { true, false })
            {
                var fromCatchPathEligible = IsRescueEligible(delAdd: true, allowReset, verified, fromCatchPath);
                var fromSeam = IsRescueEligible(delAdd: true, allowReset, verified, expectedClass);

                Assert.Equal(fromSeam, fromCatchPathEligible);
            }
        }
    }

    [Fact]
    public void ShouldAttempt_SynthesizedChangeNotPermitted_MatchesGateSemantics()
    {
        // The pre-flight (detected flag) entry point.
        Assert.True(IsRescueEligible(
            delAdd: true, allowReset: true, currentPasswordVerified: true, DirectoryFailureClass.ChangeNotPermitted));
        Assert.False(IsRescueEligible(
            delAdd: true, allowReset: false, currentPasswordVerified: true, DirectoryFailureClass.ChangeNotPermitted));
        Assert.False(IsRescueEligible(
            delAdd: true, allowReset: true, currentPasswordVerified: false, DirectoryFailureClass.ChangeNotPermitted));
        Assert.False(IsRescueEligible(
            delAdd: false, allowReset: true, currentPasswordVerified: true, DirectoryFailureClass.ChangeNotPermitted));
    }

    /// <summary>
    /// The property this whole suite exists to pin: <c>AdministrativeResetSupported</c>
    /// tracks <c>LdapChangePasswordWithDelAdd</c> in BOTH directions, exercised
    /// through a real provider instance rather than a source audit. This is the
    /// LDAP counterpart to <c>AdProviderDirectoryWriteAuditTests</c>'s source-level
    /// pin of the AD provider's equivalent override — that provider cannot be
    /// constructed off Windows, so it is audited from source; this one can be
    /// constructed here, so its guarantee is enforced behaviourally instead.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AdministrativeResetSupported_TracksLdapChangePasswordWithDelAdd(bool delAdd)
    {
        var provider = new ExposedProvider(Options(allowReset: true, delAdd: delAdd));

        Assert.Equal(delAdd, provider.ExposedAdministrativeResetSupported);
    }

    [Fact]
    public void Defaults_AllowAdministrativeResetIsOff()
    {
        Assert.False(new LdapPasswordChangeOptions().AllowAdministrativeReset);
    }
}
