using System;
using System.ComponentModel;
using System.Linq;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Tests;

public class DirectoryErrorTranslatorTests
{
    // Expected routing for every cataloged Win32 code in both disclosure modes.
    // Deliberately duplicated from the production table so that changing a
    // routing decision requires a conscious change here too.
    public static TheoryData<int, ErrorDisclosureMode, Type, ApiErrorCode, string> RoutingTable
    {
        get
        {
            var data = new TheoryData<int, ErrorDisclosureMode, Type, ApiErrorCode, string>();

            // (code, hardened expectation, informative expectation)
            foreach (var (code, hardened, informative) in new (int, Expectation, Expectation)[]
            {
                (0x005, Infra, Infra),
                (0x056, Credentials, Credentials),
                (0x523, Credentials, NotFound),
                (0x524, Infra, Infra),
                (0x525, Credentials, NotFound),
                (0x52B, Credentials, Credentials),
                (0x52C, Policy, Policy),
                (0x52D, Policy, Policy),
                (0x52E, Credentials, Credentials),
                (0x52F, Credentials, AccountState),
                (0x530, Credentials, AccountState),
                (0x531, Credentials, AccountState),
                (0x532, Credentials, Credentials),
                (0x533, Credentials, AccountState),
                (0x701, Credentials, AccountState),
                (0x773, Credentials, Credentials),
                (0x774, Infra, Infra),
                (0x775, Credentials, AccountState),
                (0x8C3, CannotChange, CannotChange),
                (0x8C4, Policy, Policy),
                (0x8C5, Policy, Policy),
                (0x8C6, Policy, Policy),
            })
            {
                data.Add(code, ErrorDisclosureMode.Hardened, hardened.ExceptionType, hardened.Code, hardened.Message);
                data.Add(code, ErrorDisclosureMode.Informative, informative.ExceptionType, informative.Code, informative.Message);
            }

            return data;
        }
    }

    private sealed record Expectation(Type ExceptionType, ApiErrorCode Code, string Message);

    private static Expectation Credentials => new(
        typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials,
        DirectoryErrorTranslator.InvalidCredentialsMessage);

    private static Expectation NotFound => new(
        typeof(UserNotFoundException), ApiErrorCode.UserNotFound,
        DirectoryErrorTranslator.UserNotFoundMessage);

    private static Expectation AccountState => new(
        typeof(PasswordPolicyViolationException), ApiErrorCode.ChangeNotPermitted,
        DirectoryErrorTranslator.AccountStateMessage);

    private static Expectation Policy => new(
        typeof(PasswordPolicyViolationException), ApiErrorCode.ComplexPassword,
        DirectoryErrorTranslator.NewPasswordPolicyMessage);

    private static Expectation CannotChange => new(
        typeof(PasswordPolicyViolationException), ApiErrorCode.ChangeNotPermitted,
        DirectoryErrorTranslator.ChangeNotPermittedMessage);

    private static Expectation Infra => new(
        typeof(DirectoryUnavailableException), ApiErrorCode.LdapProblem,
        DirectoryErrorTranslator.DirectoryFailureMessage);

    [Theory]
    [MemberData(nameof(RoutingTable))]
    public void Translate_CatalogedCode_RoutesPerTable(
        int code, ErrorDisclosureMode mode, Type exceptionType, ApiErrorCode apiCode, string message)
    {
        var inner = new InvalidOperationException("raw transport detail");

        var translated = DirectoryErrorTranslator.Translate(code, mode, inner);

        Assert.IsType(exceptionType, translated);
        Assert.Same(inner, translated.InnerException);

        var item = ApiErrorMapper.Map(translated);
        Assert.Equal(apiCode, item.ErrorCode);
        Assert.Equal(message, item.Message);
        Assert.DoesNotContain("raw transport detail", item.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RoutingTable_CoversEntireCatalogInBothModes()
    {
        var testedCodes = RoutingTable
            .Select(row => ((int)row[0], (ErrorDisclosureMode)row[1]))
            .Distinct()
            .OrderBy(pair => pair.Item1).ThenBy(pair => pair.Item2)
            .ToList();

        var expected = Win32ErrorCode.Codes
            .SelectMany(c => new[]
            {
                (c.Code, ErrorDisclosureMode.Hardened),
                (c.Code, ErrorDisclosureMode.Informative),
            })
            .OrderBy(pair => pair.Item1).ThenBy(pair => pair.Item2)
            .ToList();

        // A code added to the catalog must also get explicit per-mode routing
        // expectations here.
        Assert.Equal(expected, testedCodes);
    }

    [Fact]
    public void Translate_Hardened_WrongPasswordUnknownUserAndLockedAreByteIdentical()
    {
        // The hardened-mode guarantee: no oracle survives in the JSON.
        var wrongPassword = ApiErrorMapper.Map(DirectoryErrorTranslator.Translate(0x52E, ErrorDisclosureMode.Hardened));
        var unknownUser = ApiErrorMapper.Map(DirectoryErrorTranslator.Translate(0x525, ErrorDisclosureMode.Hardened));
        var lockedOut = ApiErrorMapper.Map(DirectoryErrorTranslator.Translate(0x775, ErrorDisclosureMode.Hardened));
        var disabled = ApiErrorMapper.Map(DirectoryErrorTranslator.Translate(0x533, ErrorDisclosureMode.Hardened));
        var structuralNotFound = ApiErrorMapper.Map(
            DirectoryErrorTranslator.CreateUserNotFoundError(ErrorDisclosureMode.Hardened));

        // Credential-verification failures do not go through the translator:
        // both providers throw InvalidCredentialsException directly, with the
        // underlying failure attached as a diagnostic inner exception. Those
        // must land on the wire byte-identically too, or the inner exception
        // would have reintroduced the oracle the rest of this test rules out.
        var verificationLockedOut = ApiErrorMapper.Map(new InvalidCredentialsException(
            DirectoryErrorTranslator.InvalidCredentialsMessage,
            CredentialFailureDetail.ForWin32Code(0x775)!));
        var verificationWrongPassword = ApiErrorMapper.Map(new InvalidCredentialsException(
            DirectoryErrorTranslator.InvalidCredentialsMessage,
            CredentialFailureDetail.ForWin32Code(0x52E)!));
        var verificationNoDetail = ApiErrorMapper.Map(new InvalidCredentialsException(
            DirectoryErrorTranslator.InvalidCredentialsMessage));

        foreach (var item in new[]
                 {
                     unknownUser, lockedOut, disabled, structuralNotFound,
                     verificationLockedOut, verificationWrongPassword, verificationNoDetail,
                 })
        {
            Assert.Equal(wrongPassword.ErrorCode, item.ErrorCode);
            Assert.Equal(wrongPassword.Message, item.Message);
        }
    }

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials)]
    [InlineData(ErrorDisclosureMode.Informative, typeof(UserNotFoundException), ApiErrorCode.UserNotFound)]
    public void CreateUserNotFoundError_FollowsDisclosureMode(
        ErrorDisclosureMode mode, Type exceptionType, ApiErrorCode apiCode)
    {
        var ex = DirectoryErrorTranslator.CreateUserNotFoundError(mode);

        Assert.IsType(exceptionType, ex);
        Assert.Equal(apiCode, ApiErrorMapper.Map(ex).ErrorCode);
    }

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public void Translate_UnknownCode_DegradesToDirectoryUnavailableInBothModes(ErrorDisclosureMode mode)
    {
        var translated = DirectoryErrorTranslator.Translate(0x9999, mode);

        var dir = Assert.IsType<DirectoryUnavailableException>(translated);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, dir.Message);
        Assert.Equal(ApiErrorCode.LdapProblem, ApiErrorMapper.Map(dir).ErrorCode);
    }

    [Fact]
    public void Translate_WithoutInnerException_Succeeds()
    {
        var translated = DirectoryErrorTranslator.Translate(0x52E, ErrorDisclosureMode.Hardened);

        Assert.IsType<InvalidCredentialsException>(translated);
        Assert.Null(translated.InnerException);
    }

    [Theory]
    [InlineData(0x9999)]
    [InlineData(0)]
    [InlineData(-1)]
    public void Classify_UnknownCode_IsInfrastructure(int code)
    {
        Assert.Equal(DirectoryFailureClass.Infrastructure, DirectoryErrorTranslator.Classify(code));
    }

    // The codes LogonUser reports in decimal are these same values — 0x532 is
    // 1330 and 0x773 is 1907 — so there is no second form to cover. Spelling
    // them out again as decimal literals produced duplicate theory cases
    // (xUnit1025), not extra coverage.
    [Theory]
    [InlineData(0x532, true)]
    [InlineData(0x773, true)]
    [InlineData(0x52E, false)]
    [InlineData(0x775, false)]
    [InlineData(0x9999, false)]
    public void IsPasswordExpiredOrMustChange_MatchesOnlyExpiredAndMustChange(int code, bool expected)
    {
        Assert.Equal(expected, DirectoryErrorTranslator.IsPasswordExpiredOrMustChange(code));
    }

    // ------------------------------------------------------------------
    // Win32 code extraction from exception chains (the AD provider's path)
    // ------------------------------------------------------------------

    [Fact]
    public void TryGetWin32Code_FacilityWin32HResult_ExtractsLowWord()
    {
        // The password-policy HRESULT observed from AccountManagement/ADSI.
        var ex = new HResultException(unchecked((int)0x800708C5));

        Assert.True(DirectoryErrorTranslator.TryGetWin32Code(ex, out var code));
        Assert.Equal(0x8C5, code);
    }

    [Fact]
    public void TryGetWin32Code_WalksPastCorHResultsToInnerCode()
    {
        // Shape of a PasswordException: COR HRESULT on the outer exception,
        // FACILITY_WIN32 HRESULT on the wrapped COM exception.
        var outer = new InvalidOperationException(
            "wrapper", new HResultException(unchecked((int)0x8007052D)));

        Assert.True(DirectoryErrorTranslator.TryGetWin32Code(outer, out var code));
        Assert.Equal(0x52D, code);
    }

    [Fact]
    public void TryGetWin32Code_Win32Exception_UsesNativeErrorCode()
    {
        var ex = new Win32Exception(1330);

        Assert.True(DirectoryErrorTranslator.TryGetWin32Code(ex, out var code));
        Assert.Equal(1330, code);
    }

    [Theory]
    [InlineData(unchecked((int)0x80004005))] // E_FAIL: facility 0, not Win32
    [InlineData(unchecked((int)0x80131500))] // COR_E_EXCEPTION: facility 0x13
    public void TryGetWin32Code_NonWin32Facility_ReturnsFalse(int hresult)
    {
        Assert.False(DirectoryErrorTranslator.TryGetWin32Code(new HResultException(hresult), out _));
    }

    [Fact]
    public void TryGetWin32Code_PlainExceptionOrNull_ReturnsFalse()
    {
        Assert.False(DirectoryErrorTranslator.TryGetWin32Code(new InvalidOperationException("no code"), out _));
        Assert.False(DirectoryErrorTranslator.TryGetWin32Code(null, out _));
    }

    // ------------------------------------------------------------------
    // TranslateException end-to-end
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public void TranslateException_PolicyHResult_MapsToComplexPasswordInBothModes(ErrorDisclosureMode mode)
    {
        // The AD automatic-context policy failure: previously escaped as
        // Generic + raw .NET message.
        var raw = new HResultException(
            unchecked((int)0x800708C5),
            "The password does not meet the password policy requirements (raw .NET text)");

        var item = ApiErrorMapper.Map(DirectoryErrorTranslator.TranslateException(raw, mode));

        Assert.Equal(ApiErrorCode.ComplexPassword, item.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.NewPasswordPolicyMessage, item.Message);
        Assert.DoesNotContain("raw .NET text", item.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TranslateException_UnrecognizableException_NeverLeaksRawText()
    {
        var raw = new InvalidOperationException("secret internal diagnostic");

        var translated = DirectoryErrorTranslator.TranslateException(raw, ErrorDisclosureMode.Hardened);

        var dir = Assert.IsType<DirectoryUnavailableException>(translated);
        Assert.Same(raw, dir.InnerException); // detail preserved for logs

        var item = ApiErrorMapper.Map(dir);
        Assert.Equal(ApiErrorCode.LdapProblem, item.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, item.Message);
        Assert.DoesNotContain("secret internal diagnostic", item.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TranslateException_WrongPasswordHResult_MapsToInvalidCredentials()
    {
        var raw = new HResultException(unchecked((int)0x80070056));

        var item = ApiErrorMapper.Map(
            DirectoryErrorTranslator.TranslateException(raw, ErrorDisclosureMode.Hardened));

        Assert.Equal(ApiErrorCode.InvalidCredentials, item.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.InvalidCredentialsMessage, item.Message);
    }

    // ------------------------------------------------------------------
    // Actor dimension: same code, different actor, different class.
    // A service-account failure can never surface as an end-user credential,
    // existence, or account-state result.
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(0x52E)] // ERROR_LOGON_FAILURE (Credentials)
    [InlineData(0x56)]  // ERROR_INVALID_PASSWORD (Credentials)
    [InlineData(0x52B)] // ERROR_WRONG_PASSWORD (Credentials)
    [InlineData(0x525)] // ERROR_NO_SUCH_USER (Existence)
    [InlineData(0x523)] // ERROR_INVALID_ACCOUNT_NAME (Existence)
    [InlineData(0x775)] // ERROR_ACCOUNT_LOCKED_OUT (AccountState)
    [InlineData(0x533)] // ERROR_ACCOUNT_DISABLED (AccountState)
    [InlineData(0x532)] // ERROR_PASSWORD_EXPIRED (PasswordExpiredOrMustChange — must NOT "proceed" for the service account)
    [InlineData(0x773)] // ERROR_PASSWORD_MUST_CHANGE (PasswordExpiredOrMustChange)
    public void ClassifyForActor_ServiceAccount_CoercesEndUserSignalsToInfrastructure(int code)
    {
        // As the user, these are genuine end-user account signals...
        Assert.NotEqual(DirectoryFailureClass.Infrastructure,
            DirectoryErrorTranslator.ClassifyForActor(code, DirectoryActor.User));
        // ...but as the service account they are meaningless to the caller.
        Assert.Equal(DirectoryFailureClass.Infrastructure,
            DirectoryErrorTranslator.ClassifyForActor(code, DirectoryActor.ServiceAccount));
    }

    [Theory]
    [InlineData(0x52D, DirectoryFailureClass.NewPasswordPolicy)]
    [InlineData(0x8C3, DirectoryFailureClass.ChangeNotPermitted)]
    [InlineData(0x5, DirectoryFailureClass.Infrastructure)]
    public void ClassifyForActor_ServiceAccount_LeavesNonEndUserSignalClassesUntouched(
        int code, DirectoryFailureClass expected)
    {
        Assert.Equal(expected, DirectoryErrorTranslator.ClassifyForActor(code, DirectoryActor.ServiceAccount));
        Assert.Equal(expected, DirectoryErrorTranslator.ClassifyForActor(code, DirectoryActor.User));
    }

    [Theory]
    [InlineData(0x52E, ErrorDisclosureMode.Hardened)]
    [InlineData(0x52E, ErrorDisclosureMode.Informative)]
    [InlineData(0x775, ErrorDisclosureMode.Hardened)]
    [InlineData(0x775, ErrorDisclosureMode.Informative)]
    [InlineData(0x532, ErrorDisclosureMode.Hardened)]  // the expired case: never "proceed" for the service account
    [InlineData(0x532, ErrorDisclosureMode.Informative)]
    [InlineData(0x525, ErrorDisclosureMode.Hardened)]
    [InlineData(0x525, ErrorDisclosureMode.Informative)]
    public void Translate_ServiceAccount_YieldsInfrastructure_NeverCredentials(int code, ErrorDisclosureMode mode)
    {
        var item = ApiErrorMapper.Map(DirectoryErrorTranslator.Translate(code, mode, DirectoryActor.ServiceAccount));

        Assert.Equal(ApiErrorCode.LdapProblem, item.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, item.Message);
    }

    [Fact]
    public void Translate_ServiceAccount_NoCatalogCodeEverProducesCredentialsOrUserNotFound()
    {
        // The core invariant, exhaustively: whatever a service-account operation
        // fails with, the end user never sees an account-existence or credential
        // signal.
        foreach (var entry in Win32ErrorCode.Codes)
        {
            foreach (var mode in new[] { ErrorDisclosureMode.Hardened, ErrorDisclosureMode.Informative })
            {
                var item = ApiErrorMapper.Map(
                    DirectoryErrorTranslator.Translate(entry.Code, mode, DirectoryActor.ServiceAccount));

                Assert.NotEqual(ApiErrorCode.InvalidCredentials, item.ErrorCode);
                Assert.NotEqual(ApiErrorCode.UserNotFound, item.ErrorCode);
            }
        }
    }

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public void Translate_User_StillYieldsInvalidCredentials_RegressionGuard(ErrorDisclosureMode mode)
    {
        // The fix must not over-correct: the end user's own wrong password is
        // still invalid credentials.
        var item = ApiErrorMapper.Map(DirectoryErrorTranslator.Translate(0x52E, mode, DirectoryActor.User));
        Assert.Equal(ApiErrorCode.InvalidCredentials, item.ErrorCode);
    }

    [Fact]
    public void TranslateException_ServiceAccountHResult_MapsToInfrastructure()
    {
        // The exact call the AD provider's RunAsServiceAccount makes: a
        // FACILITY_WIN32 logon-failure HRESULT from AccountManagement.
        var raw = new HResultException(unchecked((int)0x8007052E), "raw AccountManagement text");

        var item = ApiErrorMapper.Map(DirectoryErrorTranslator.TranslateException(
            raw, ErrorDisclosureMode.Hardened, DirectoryActor.ServiceAccount, out var failureClass));

        Assert.Equal(DirectoryFailureClass.Infrastructure, failureClass);
        Assert.Equal(ApiErrorCode.LdapProblem, item.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, item.Message);
        Assert.DoesNotContain("raw AccountManagement text", item.Message, StringComparison.Ordinal);
    }

    // ------------------------------------------------------------------
    // C-4: terminal-catch consistency. Both providers' last-resort
    // catch (Exception) now constructs DirectoryUnavailableException directly.
    // For the non-directory exceptions that actually reach it, that produces
    // the same wire result the former AD-side TranslateException did — so the
    // standardization is behavior-preserving for the expected input, and both
    // providers land on the same infrastructure result.
    // ------------------------------------------------------------------

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public void TerminalCatch_NonDirectoryException_YieldsInfrastructureIdenticallyToFormerAdBehavior(
        ErrorDisclosureMode mode)
    {
        var nonDirectory = new InvalidOperationException("unexpected non-directory fault");

        // What both providers' terminal catch now does (direct construction).
        var standardized = ApiErrorMapper.Map(
            new DirectoryUnavailableException(DirectoryErrorTranslator.DirectoryFailureMessage, nonDirectory));

        // What the AD provider's terminal catch used to do (chain re-scan). For a
        // non-directory exception there is no Win32 code to find, so it degrades
        // to the same infrastructure result — proving the change is safe.
        var formerAd = ApiErrorMapper.Map(
            DirectoryErrorTranslator.TranslateException(nonDirectory, mode));

        Assert.Equal(ApiErrorCode.LdapProblem, standardized.ErrorCode);
        Assert.Equal(standardized.ErrorCode, formerAd.ErrorCode);
        Assert.Equal(standardized.Message, formerAd.Message);
        Assert.DoesNotContain("non-directory fault", standardized.Message!, StringComparison.Ordinal);
    }

    private sealed class HResultException : Exception
    {
        public HResultException(int hresult, string message = "test", Exception? inner = null)
            : base(message, inner)
        {
            HResult = hresult;
        }
    }
}
