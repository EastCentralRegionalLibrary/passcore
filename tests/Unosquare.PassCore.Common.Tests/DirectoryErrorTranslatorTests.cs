using System;
using System.ComponentModel;
using System.Linq;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Tests;

public class DirectoryErrorTranslatorTests
{
    // Expected routing for every cataloged Win32 code. Deliberately duplicated
    // from the production table so that changing a routing decision requires a
    // conscious change here too.
    public static TheoryData<int, Type, ApiErrorCode, string> RoutingTable => new()
    {
        { 0x005, typeof(DirectoryUnavailableException), ApiErrorCode.LdapProblem, DirectoryErrorTranslator.DirectoryFailureMessage },
        { 0x056, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x523, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x524, typeof(DirectoryUnavailableException), ApiErrorCode.LdapProblem, DirectoryErrorTranslator.DirectoryFailureMessage },
        { 0x525, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x52B, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x52C, typeof(PasswordPolicyViolationException), ApiErrorCode.ComplexPassword, DirectoryErrorTranslator.NewPasswordPolicyMessage },
        { 0x52D, typeof(PasswordPolicyViolationException), ApiErrorCode.ComplexPassword, DirectoryErrorTranslator.NewPasswordPolicyMessage },
        { 0x52E, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x52F, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x530, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x531, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x532, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x533, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x701, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x773, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x774, typeof(DirectoryUnavailableException), ApiErrorCode.LdapProblem, DirectoryErrorTranslator.DirectoryFailureMessage },
        { 0x775, typeof(InvalidCredentialsException), ApiErrorCode.InvalidCredentials, DirectoryErrorTranslator.InvalidCredentialsMessage },
        { 0x8C3, typeof(PasswordPolicyViolationException), ApiErrorCode.ChangeNotPermitted, DirectoryErrorTranslator.ChangeNotPermittedMessage },
        { 0x8C4, typeof(PasswordPolicyViolationException), ApiErrorCode.ComplexPassword, DirectoryErrorTranslator.NewPasswordPolicyMessage },
        { 0x8C5, typeof(PasswordPolicyViolationException), ApiErrorCode.ComplexPassword, DirectoryErrorTranslator.NewPasswordPolicyMessage },
        { 0x8C6, typeof(PasswordPolicyViolationException), ApiErrorCode.ComplexPassword, DirectoryErrorTranslator.NewPasswordPolicyMessage },
    };

    [Theory]
    [MemberData(nameof(RoutingTable))]
    public void Translate_CatalogedCode_RoutesPerTable(int code, Type exceptionType, ApiErrorCode apiCode, string message)
    {
        var inner = new InvalidOperationException("raw transport detail");

        var translated = DirectoryErrorTranslator.Translate(code, inner);

        Assert.IsType(exceptionType, translated);
        Assert.Same(inner, translated.InnerException);

        var item = ApiErrorMapper.Map(translated);
        Assert.Equal(apiCode, item.ErrorCode);
        Assert.Equal(message, item.Message);
        Assert.DoesNotContain("raw transport detail", item.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void RoutingTable_CoversEntireCatalog()
    {
        var testedCodes = RoutingTable.Select(row => (int)row[0]).OrderBy(c => c);
        var catalogedCodes = Win32ErrorCode.Codes.Select(c => c.Code).OrderBy(c => c);

        // A code added to the catalog must also get an explicit routing expectation here.
        Assert.Equal(catalogedCodes, testedCodes);
    }

    [Fact]
    public void Translate_UnknownCode_DegradesToDirectoryUnavailable()
    {
        var translated = DirectoryErrorTranslator.Translate(0x9999);

        var dir = Assert.IsType<DirectoryUnavailableException>(translated);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, dir.Message);
        Assert.Equal(ApiErrorCode.LdapProblem, ApiErrorMapper.Map(dir).ErrorCode);
    }

    [Fact]
    public void Translate_WithoutInnerException_Succeeds()
    {
        var translated = DirectoryErrorTranslator.Translate(0x52E);

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

    [Fact]
    public void TranslateException_PolicyHResult_MapsToComplexPassword()
    {
        // The AD automatic-context policy failure: previously escaped as
        // Generic + raw .NET message.
        var raw = new HResultException(
            unchecked((int)0x800708C5),
            "The password does not meet the password policy requirements (raw .NET text)");

        var item = ApiErrorMapper.Map(DirectoryErrorTranslator.TranslateException(raw));

        Assert.Equal(ApiErrorCode.ComplexPassword, item.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.NewPasswordPolicyMessage, item.Message);
        Assert.DoesNotContain("raw .NET text", item.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TranslateException_UnrecognizableException_NeverLeaksRawText()
    {
        var raw = new InvalidOperationException("secret internal diagnostic");

        var translated = DirectoryErrorTranslator.TranslateException(raw);

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

        var item = ApiErrorMapper.Map(DirectoryErrorTranslator.TranslateException(raw));

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
