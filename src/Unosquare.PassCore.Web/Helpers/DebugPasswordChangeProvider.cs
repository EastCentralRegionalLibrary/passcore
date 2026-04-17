using System.Threading.Tasks;
using PwnedPasswordsSearch;
namespace Unosquare.PassCore.Web.Helpers;

internal class DebugPasswordChangeProvider : IPasswordChangeProvider
{
    private readonly IPwnedPasswordSearch _pwnedPasswordSearch;
    public DebugPasswordChangeProvider(IPwnedPasswordSearch pwnedPasswordSearch) => _pwnedPasswordSearch = pwnedPasswordSearch;

    public async Task<ApiErrorItem?> PerformPasswordChangeAsync(string username, string currentPassword, string newPassword)
    {
        var currentUsername = username.IndexOf("@", StringComparison.Ordinal) > 0
            ? username[..username.IndexOf("@", StringComparison.Ordinal)]
            : username;

        // Even in DEBUG, it is safe to make this call and check the password anyway
        if (await _pwnedPasswordSearch.IsPwnedPasswordAsync(newPassword))
            return new ApiErrorItem(ApiErrorCode.PwnedPassword);

        return currentUsername switch
        {
            "error" => new ApiErrorItem(ApiErrorCode.Generic, "Error"),
            "changeNotPermitted" => new ApiErrorItem(ApiErrorCode.ChangeNotPermitted),
            "fieldMismatch" => new ApiErrorItem(ApiErrorCode.FieldMismatch),
            "fieldRequired" => new ApiErrorItem(ApiErrorCode.FieldRequired),
            "invalidCaptcha" => new ApiErrorItem(ApiErrorCode.InvalidCaptcha),
            "invalidCredentials" => new ApiErrorItem(ApiErrorCode.InvalidCredentials),
            "invalidDomain" => new ApiErrorItem(ApiErrorCode.InvalidDomain),
            "userNotFound" => new ApiErrorItem(ApiErrorCode.UserNotFound),
            "ldapProblem" => new ApiErrorItem(ApiErrorCode.LdapProblem),
            "pwnedPassword" => new ApiErrorItem(ApiErrorCode.PwnedPassword),
            _ => null
        };
    }
}