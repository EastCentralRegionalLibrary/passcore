using Novell.Directory.Ldap;
using Unosquare.PassCore.Common;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// Phase 4 empirical consistency audit. Re-derives, from the merged code
/// (not from documentation), that the two real providers now route every
/// directory condition identically, in both disclosure modes and both
/// administrative-reset states — the property the whole series set out to
/// establish. The values asserted here are the source of truth transcribed
/// into <c>docs/error-routing-matrix.md</c>; if a routing decision changes,
/// this test and that document must change together.
///
/// The AD provider is Windows-only and cannot be compiled or run on the
/// cross-platform CI host, so its column is exercised through
/// <see cref="DirectoryErrorTranslator.TranslateException"/> — the exact call
/// its catch block delegates to (verified by reading
/// <c>PasswordChangeProvider.cs</c>). The LDAP column runs the provider's real
/// <see cref="LdapPasswordChangeProvider.TranslateLdapException(LdapException, ErrorDisclosureMode)"/>.
/// </summary>
public class RoutingMatrixAuditTests
{
    private readonly record struct Wire(ApiErrorCode Code, string? Message)
    {
        public static Wire Of(System.Exception domainException)
        {
            var item = ApiErrorMapper.Map(domainException);
            return new Wire(item.ErrorCode, item.Message);
        }
    }

    // The same underlying Win32 code, rendered through each transport a real
    // provider would receive it in.
    private static Wire ViaLdapBind(int code, ErrorDisclosureMode mode) =>
        Wire.Of(LdapPasswordChangeProvider.TranslateLdapException(
            new LdapException("t", LdapException.InvalidCredentials,
                $"80090308: LdapErr: DSID-0C090439, comment: AcceptSecurityContext error, data {code:x}, v3839"),
            mode));

    private static Wire ViaLdapModify(int code, ErrorDisclosureMode mode) =>
        Wire.Of(LdapPasswordChangeProvider.TranslateLdapException(
            new LdapException("t", LdapException.UnwillingToPerform,
                $"{code:X8}: SvcErr: DSID-031A12D2, problem 5003 (WILL_NOT_PERFORM), data 0"),
            mode));

    private static Wire ViaAdHResult(int code, ErrorDisclosureMode mode) =>
        Wire.Of(DirectoryErrorTranslator.TranslateException(
            new HResultException(unchecked((int)0x80070000 | code)), mode));

    // ------------------------------------------------------------------
    // 1. Full catalog: every code, every transport, every mode converges.
    // ------------------------------------------------------------------

    public static TheoryData<int, ErrorDisclosureMode> CatalogXMode
    {
        get
        {
            var data = new TheoryData<int, ErrorDisclosureMode>();
            foreach (var entry in Win32ErrorCode.Codes)
            {
                data.Add(entry.Code, ErrorDisclosureMode.Hardened);
                data.Add(entry.Code, ErrorDisclosureMode.Informative);
            }

            return data;
        }
    }

    [Theory]
    [MemberData(nameof(CatalogXMode))]
    public void EveryCode_AllThreeTransports_ProduceOneWireResult(int code, ErrorDisclosureMode mode)
    {
        var ldapBind = ViaLdapBind(code, mode);
        var ldapModify = ViaLdapModify(code, mode);
        var adHResult = ViaAdHResult(code, mode);

        Assert.Equal(ldapBind, ldapModify);
        Assert.Equal(ldapBind, adHResult);

        // The class the catalog assigns must be what actually drives the result.
        var expected = ExpectedWire(DirectoryErrorTranslator.Classify(code), mode);
        Assert.Equal(expected, ldapBind);
    }

    // ------------------------------------------------------------------
    // 2. Canonical matrix: class x mode -> (code, message). This is the
    //    table in docs/error-routing-matrix.md.
    // ------------------------------------------------------------------

    public static TheoryData<DirectoryFailureClass, ErrorDisclosureMode, ApiErrorCode, string?> Matrix => new()
    {
        // class, mode, expected ApiErrorCode, expected wire message
        { DirectoryFailureClass.Credentials, ErrorDisclosureMode.Hardened, ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { DirectoryFailureClass.Credentials, ErrorDisclosureMode.Informative, ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { DirectoryFailureClass.PasswordExpiredOrMustChange, ErrorDisclosureMode.Hardened, ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { DirectoryFailureClass.PasswordExpiredOrMustChange, ErrorDisclosureMode.Informative, ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { DirectoryFailureClass.Existence, ErrorDisclosureMode.Hardened, ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { DirectoryFailureClass.Existence, ErrorDisclosureMode.Informative, ApiErrorCode.UserNotFound, DirectoryErrorTranslator.UserNotFoundMessage },
        { DirectoryFailureClass.AccountState, ErrorDisclosureMode.Hardened, ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { DirectoryFailureClass.AccountState, ErrorDisclosureMode.Informative, ApiErrorCode.ChangeNotPermitted, DirectoryErrorTranslator.AccountStateMessage },
        { DirectoryFailureClass.NewPasswordPolicy, ErrorDisclosureMode.Hardened, ApiErrorCode.ComplexPassword, DirectoryErrorTranslator.NewPasswordPolicyMessage },
        { DirectoryFailureClass.NewPasswordPolicy, ErrorDisclosureMode.Informative, ApiErrorCode.ComplexPassword, DirectoryErrorTranslator.NewPasswordPolicyMessage },
        { DirectoryFailureClass.ChangeNotPermitted, ErrorDisclosureMode.Hardened, ApiErrorCode.ChangeNotPermitted, DirectoryErrorTranslator.ChangeNotPermittedMessage },
        { DirectoryFailureClass.ChangeNotPermitted, ErrorDisclosureMode.Informative, ApiErrorCode.ChangeNotPermitted, DirectoryErrorTranslator.ChangeNotPermittedMessage },
        { DirectoryFailureClass.Infrastructure, ErrorDisclosureMode.Hardened, ApiErrorCode.LdapProblem, DirectoryErrorTranslator.DirectoryFailureMessage },
        { DirectoryFailureClass.Infrastructure, ErrorDisclosureMode.Informative, ApiErrorCode.LdapProblem, DirectoryErrorTranslator.DirectoryFailureMessage },
    };

    [Theory]
    [MemberData(nameof(Matrix))]
    public void CanonicalMatrix_MatchesTranslatorOutput(
        DirectoryFailureClass failureClass, ErrorDisclosureMode mode, ApiErrorCode expectedCode, string? expectedMessage)
    {
        Assert.Equal(new Wire(expectedCode, expectedMessage), ExpectedWire(failureClass, mode));
    }

    [Fact]
    public void CanonicalMatrix_CoversEveryFailureClassInBothModes()
    {
        var covered = Matrix.Select(r => ((DirectoryFailureClass)r[0]!, (ErrorDisclosureMode)r[1]!)).ToHashSet();
        foreach (var failureClass in System.Enum.GetValues<DirectoryFailureClass>())
        {
            Assert.Contains((failureClass, ErrorDisclosureMode.Hardened), covered);
            Assert.Contains((failureClass, ErrorDisclosureMode.Informative), covered);
        }
    }

    // ------------------------------------------------------------------
    // 3. The reset-fallback dimension: only ChangeNotPermitted flips between
    //    the two fallback states; everything else is identical on/off.
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(DirectoryFailureClass.ChangeNotPermitted, true)]
    [InlineData(DirectoryFailureClass.NewPasswordPolicy, false)]
    [InlineData(DirectoryFailureClass.AccountState, false)]
    [InlineData(DirectoryFailureClass.Credentials, false)]
    [InlineData(DirectoryFailureClass.Existence, false)]
    [InlineData(DirectoryFailureClass.Infrastructure, false)]
    [InlineData(DirectoryFailureClass.PasswordExpiredOrMustChange, false)]
    public void ResetFallback_OnlyChangeNotPermittedIsRescuable(DirectoryFailureClass failureClass, bool rescuableWhenOn)
    {
        // Verified (option on) always equals the class-eligibility; off is always false.
        Assert.Equal(rescuableWhenOn, AdministrativeReset.ShouldAttempt(
            allowAdministrativeReset: true, currentCredentialsVerified: true, failureClass));
        Assert.False(AdministrativeReset.ShouldAttempt(
            allowAdministrativeReset: false, currentCredentialsVerified: true, failureClass));
    }

    // ------------------------------------------------------------------
    // 4. The original divergence table (top of the task brief), re-derived
    //    for the merged state. Each row asserts the two providers now agree.
    // ------------------------------------------------------------------

    [Theory]
    // "User not found"        -> hardened: both InvalidCredentials; informative: both UserNotFound
    [InlineData(0x525, ErrorDisclosureMode.Hardened, ApiErrorCode.InvalidCredentials)]
    [InlineData(0x525, ErrorDisclosureMode.Informative, ApiErrorCode.UserNotFound)]
    // "Locked / disabled / logon-hours" -> hardened InvalidCredentials; informative ChangeNotPermitted
    [InlineData(0x775, ErrorDisclosureMode.Hardened, ApiErrorCode.InvalidCredentials)]
    [InlineData(0x775, ErrorDisclosureMode.Informative, ApiErrorCode.ChangeNotPermitted)]
    // "UserCannotChangePassword flag" -> ChangeNotPermitted in both modes
    [InlineData(0x8C3, ErrorDisclosureMode.Hardened, ApiErrorCode.ChangeNotPermitted)]
    [InlineData(0x8C3, ErrorDisclosureMode.Informative, ApiErrorCode.ChangeNotPermitted)]
    // "New password fails domain policy" -> ComplexPassword in both modes
    [InlineData(0x52D, ErrorDisclosureMode.Hardened, ApiErrorCode.ComplexPassword)]
    [InlineData(0x52D, ErrorDisclosureMode.Informative, ApiErrorCode.ComplexPassword)]
    // "DC unreachable / service acct misconfigured" -> LdapProblem in both modes
    [InlineData(0x5, ErrorDisclosureMode.Hardened, ApiErrorCode.LdapProblem)]
    [InlineData(0x5, ErrorDisclosureMode.Informative, ApiErrorCode.LdapProblem)]
    public void OriginalDivergenceTable_ConvergesAcrossProviders(int code, ErrorDisclosureMode mode, ApiErrorCode expected)
    {
        var ldap = ViaLdapBind(code, mode);
        var ad = ViaAdHResult(code, mode);

        Assert.Equal(expected, ldap.Code);
        Assert.Equal(ldap, ad); // same code AND same wire message across providers
    }

    [Theory]
    [InlineData(0x532)] // expired
    [InlineData(0x773)] // must-change
    public void OriginalDivergenceTable_ExpiredMustChange_AllowedThroughOnBothProviders(int code)
    {
        // Both providers treat these as proof of the current password during
        // verification (they never reach change-time translation). The shared
        // definition backs both.
        Assert.True(DirectoryErrorTranslator.IsPasswordExpiredOrMustChange(code));
    }

    private static Wire ExpectedWire(DirectoryFailureClass failureClass, ErrorDisclosureMode mode)
    {
        // Drive an exception of the given class through the translator by using
        // a representative catalog code, then map it — the same path a provider
        // takes. Structural cannot-change (no code) uses the dedicated factory.
        var code = failureClass switch
        {
            DirectoryFailureClass.Credentials => 0x52E,
            DirectoryFailureClass.Existence => 0x525,
            DirectoryFailureClass.AccountState => 0x775,
            DirectoryFailureClass.NewPasswordPolicy => 0x52D,
            DirectoryFailureClass.ChangeNotPermitted => 0x8C3,
            DirectoryFailureClass.PasswordExpiredOrMustChange => 0x532,
            _ => 0x5,
        };

        return Wire.Of(DirectoryErrorTranslator.Translate(code, mode));
    }

    private sealed class HResultException : System.Exception
    {
        public HResultException(int hresult) : base("raw transport detail") => HResult = hresult;
    }
}
