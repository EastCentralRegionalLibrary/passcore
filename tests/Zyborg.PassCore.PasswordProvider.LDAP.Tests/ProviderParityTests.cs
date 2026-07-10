using Novell.Directory.Ldap;
using Unosquare.PassCore.Common;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// Asserts that the same underlying Win32/AD condition produces an identical
/// <see cref="ApiErrorItem"/> (code and message) regardless of the transport
/// that surfaced it: an LDAP bind-style extended error, an LDAP modify-style
/// extended error, or a COM-style HRESULT as unwrapped from an
/// AccountManagement exception chain. The first two run through the LDAP
/// provider's real translation entry point; the third runs through
/// <see cref="DirectoryErrorTranslator.TranslateException"/>, which is the
/// exact call the Windows AD provider's catch block delegates to (that
/// provider is compiled only on Windows, so its two-line glue cannot be
/// exercised by this cross-platform suite — noted limitation).
/// </summary>
public class ProviderParityTests
{
    public static TheoryData<int> CatalogedCodes
    {
        get
        {
            var data = new TheoryData<int>();
            foreach (var entry in Win32ErrorCode.Codes)
                data.Add(entry.Code);
            return data;
        }
    }

    [Theory]
    [MemberData(nameof(CatalogedCodes))]
    public void AllTransports_SameWin32Code_ProduceIdenticalApiErrorItems(int code)
    {
        // LDAP transport, bind-style: generic SEC_E leading code, Win32 code in "data".
        var bindStyle = new LdapException("test", LdapException.InvalidCredentials,
            $"80090308: LdapErr: DSID-0C090439, comment: AcceptSecurityContext error, data {code:x}, v3839");

        // LDAP transport, modify-style: Win32 code leading, "data 0".
        var modifyStyle = new LdapException("test", LdapException.UnwillingToPerform,
            $"{code:X8}: SvcErr: DSID-031A12D2, problem 5003 (WILL_NOT_PERFORM), data 0");

        // AD transport: FACILITY_WIN32 HRESULT (e.g. 0x800708C5 for 0x8C5), the
        // shape AccountManagement wraps around COM errors.
        var adStyle = new HResultException(unchecked((int)0x80070000 | code));

        var fromBind = ApiErrorMapper.Map(LdapPasswordChangeProvider.TranslateLdapException(bindStyle));
        var fromModify = ApiErrorMapper.Map(LdapPasswordChangeProvider.TranslateLdapException(modifyStyle));
        var fromHResult = ApiErrorMapper.Map(DirectoryErrorTranslator.TranslateException(adStyle));

        Assert.Equal(fromBind.ErrorCode, fromModify.ErrorCode);
        Assert.Equal(fromBind.ErrorCode, fromHResult.ErrorCode);
        Assert.Equal(fromBind.Message, fromModify.Message);
        Assert.Equal(fromBind.Message, fromHResult.Message);

        // No transport diagnostic text may survive to the wire message.
        Assert.NotNull(fromBind.Message);
        Assert.DoesNotContain("DSID", fromBind.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("DSID", fromModify.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AllTransports_UnknownCode_ProduceIdenticalInfrastructureItems()
    {
        const int unknownCode = 0x9999;

        var bindStyle = new LdapException("test", LdapException.InvalidCredentials,
            $"80090308: LdapErr: DSID-0C090439, comment: AcceptSecurityContext error, data {unknownCode:x}, v3839");
        var adStyle = new HResultException(unchecked((int)0x80070000 | unknownCode));

        var fromBind = ApiErrorMapper.Map(LdapPasswordChangeProvider.TranslateLdapException(bindStyle));
        var fromHResult = ApiErrorMapper.Map(DirectoryErrorTranslator.TranslateException(adStyle));

        Assert.Equal(ApiErrorCode.LdapProblem, fromBind.ErrorCode);
        Assert.Equal(fromBind.ErrorCode, fromHResult.ErrorCode);
        Assert.Equal(fromBind.Message, fromHResult.Message);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, fromBind.Message);
    }

    private sealed class HResultException : Exception
    {
        public HResultException(int hresult)
            : base("raw transport detail")
        {
            HResult = hresult;
        }
    }
}
