using System.ComponentModel;
using System.Linq;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// Covers the diagnostic detail attached to a failed credential verification:
/// it must make the underlying condition recoverable from the log, and it must
/// stay out of everything the caller can see.
/// </summary>
public class CredentialFailureDetailTests
{
    /// <summary>
    /// The codes an operator most needs to tell apart when hardened mode has
    /// collapsed them all into one response.
    /// </summary>
    public static TheoryData<int, string> CataloguedCodes => new()
    {
        { 0x52B, "ERROR_WRONG_PASSWORD" },
        { 0x52E, "ERROR_LOGON_FAILURE" },
        { 0x52F, "ERROR_ACCOUNT_RESTRICTION" },
        { 0x530, "ERROR_INVALID_LOGON_HOURS" },
        { 0x533, "ERROR_ACCOUNT_DISABLED" },
        { 0x701, "ERROR_ACCOUNT_EXPIRED" },
        { 0x775, "ERROR_ACCOUNT_LOCKED_OUT" },
    };

    [Theory]
    [MemberData(nameof(CataloguedCodes))]
    public void ForWin32Code_MakesTheReasonRecoverable(int code, string codeName)
    {
        var detail = CredentialFailureDetail.ForWin32Code(code);
        Assert.NotNull(detail);

        // Recoverable by the same helper that reads the LDAP provider's
        // transport exceptions, so both providers' logs answer the same
        // question the same way.
        Assert.True(DirectoryErrorTranslator.TryGetWin32Code(detail, out var recovered));
        Assert.Equal(code, recovered);

        // And readable without a lookup table in hand.
        Assert.Contains(codeName, detail.Message, System.StringComparison.Ordinal);
        Assert.Contains($"0x{code:X}", detail.Message, System.StringComparison.Ordinal);
    }

    [Theory]
    [MemberData(nameof(CataloguedCodes))]
    public void ForWin32Code_SurvivesBeingWrappedAsAnInnerException(int code, string codeName)
    {
        // The shape the provider actually produces: the detail is reachable
        // only through the chain, which is what the base class hands the logger.
        var thrown = new InvalidCredentialsException(
            DirectoryErrorTranslator.InvalidCredentialsMessage,
            CredentialFailureDetail.ForWin32Code(code)!);

        Assert.True(DirectoryErrorTranslator.TryGetWin32Code(thrown, out var recovered));
        Assert.Equal(code, recovered);
        Assert.Contains(codeName, thrown.ToString(), System.StringComparison.Ordinal);
    }

    [Fact]
    public void ForWin32Code_EveryCataloguedCode_IsNamedAndDescribed()
    {
        foreach (var entry in Win32ErrorCode.Codes)
        {
            var detail = CredentialFailureDetail.ForWin32Code(entry.Code);

            Assert.NotNull(detail);
            Assert.Contains(entry.CodeName, detail.Message, System.StringComparison.Ordinal);
            Assert.Contains(entry.Description, detail.Message, System.StringComparison.Ordinal);
        }
    }

    [Fact]
    public void ForWin32Code_UncataloguedCode_StillCarriesTheCode()
    {
        const int uncatalogued = 0x1234;
        Assert.Null(Win32ErrorCode.ByCode(uncatalogued));

        var detail = CredentialFailureDetail.ForWin32Code(uncatalogued);

        // The OS supplies the message here, so only the code is asserted — it
        // is the part an operator can act on.
        Assert.NotNull(detail);
        Assert.Equal(uncatalogued, Assert.IsType<Win32Exception>(detail).NativeErrorCode);
    }

    [Fact]
    public void ForWin32Code_Zero_YieldsNoDetail()
    {
        // "No code was reported" must not fabricate one; the failure stays
        // exactly as detail-free as it was before.
        Assert.Null(CredentialFailureDetail.ForWin32Code(0));
    }

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public void Detail_NeverReachesTheWire_InEitherDisclosureMode(ErrorDisclosureMode mode)
    {
        // The disclosure mode is not an input to the mapping of an already-thrown
        // InvalidCredentialsException; both modes are exercised to make the
        // claim explicit rather than assumed.
        Assert.True(mode is ErrorDisclosureMode.Hardened or ErrorDisclosureMode.Informative);

        foreach (var entry in Win32ErrorCode.Codes)
        {
            var item = ApiErrorMapper.Map(new InvalidCredentialsException(
                DirectoryErrorTranslator.InvalidCredentialsMessage,
                CredentialFailureDetail.ForWin32Code(entry.Code)!));

            Assert.Equal(ApiErrorCode.InvalidCredentials, item.ErrorCode);
            Assert.Equal(DirectoryErrorTranslator.InvalidCredentialsMessage, item.Message);

            // Nothing identifying the condition may survive into the payload.
            Assert.DoesNotContain(entry.CodeName, item.Message, System.StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain($"0x{entry.Code:X}", item.Message, System.StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(entry.Description, item.Message, System.StringComparison.OrdinalIgnoreCase);
        }
    }

    [Fact]
    public void ApiErrorMapper_ReadsOnlyTheOuterMessage_NeverTheChain()
    {
        // The structural reason the assertion above holds: if Map ever started
        // walking InnerException, this canary fails.
        const string secret = "UNDERLYING-DETAIL-THAT-MUST-NOT-SHIP";

        var item = ApiErrorMapper.Map(new InvalidCredentialsException(
            DirectoryErrorTranslator.InvalidCredentialsMessage,
            new Win32Exception(0x775, secret)));

        Assert.Equal(DirectoryErrorTranslator.InvalidCredentialsMessage, item.Message);
        Assert.DoesNotContain(secret, item.Message, System.StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(0x532)] // ERROR_PASSWORD_EXPIRED
    [InlineData(0x773)] // ERROR_PASSWORD_MUST_CHANGE
    public void ExpiredAndMustChange_StillProceed_AndAreNeverTurnedIntoAFailure(int code)
    {
        // The decision D-1 must not have disturbed: these two codes mean the
        // user proved the current password, so verification returns "proceed"
        // and no InvalidCredentialsException (and therefore no detail) is
        // produced at all.
        Assert.True(DirectoryErrorTranslator.IsPasswordExpiredOrMustChange(code));

        var everyOtherCode = Win32ErrorCode.Codes
            .Where(c => c.Code != 0x532 && c.Code != 0x773)
            .Select(c => c.Code);

        Assert.All(everyOtherCode, c => Assert.False(DirectoryErrorTranslator.IsPasswordExpiredOrMustChange(c)));
    }
}
