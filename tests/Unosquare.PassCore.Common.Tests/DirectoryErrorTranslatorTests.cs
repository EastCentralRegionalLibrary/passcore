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

        foreach (var item in new[] { unknownUser, lockedOut, disabled, structuralNotFound })
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

    [Theory]
    [InlineData(0x532, true)]
    [InlineData(0x773, true)]
    [InlineData(1330, true)]  // 0x532 as LogonUser reports it (decimal)
    [InlineData(1907, true)]  // 0x773 as LogonUser reports it (decimal)
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

    private sealed class HResultException : Exception
    {
        public HResultException(int hresult, string message = "test", Exception? inner = null)
            : base(message, inner)
        {
            HResult = hresult;
        }
    }
}
