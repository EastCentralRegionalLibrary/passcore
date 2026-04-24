using System;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Helper class to map exceptions to ApiErrorItem.
/// </summary>
public static class ApiErrorMapper
{
    /// <summary>
    /// Maps an exception to an ApiErrorItem.
    /// </summary>
    /// <param name="ex">The exception.</param>
    /// <returns>The mapped ApiErrorItem.</returns>
    public static ApiErrorItem Map(Exception ex)
    {
        ArgumentNullException.ThrowIfNull(ex);

        return ex switch
        {
            InvalidCredentialsException => new ApiErrorItem(ApiErrorCode.InvalidCredentials, ex.Message),
            PasswordPolicyViolationException policyEx => new ApiErrorItem(policyEx.ErrorCode, ex.Message),
            UserNotFoundException => new ApiErrorItem(ApiErrorCode.UserNotFound, ex.Message),
            DirectoryUnavailableException => new ApiErrorItem(ApiErrorCode.LdapProblem, ex.Message),
            ApiErrorException apiEx => apiEx.ToApiErrorItem(),
            _ => new ApiErrorItem(ApiErrorCode.Generic, ex.InnerException?.Message ?? ex.Message)
        };
    }
}
