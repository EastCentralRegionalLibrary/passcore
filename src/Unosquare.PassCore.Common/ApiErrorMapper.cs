using System;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Helper to map exceptions to API error items.
/// </summary>
public static class ApiErrorMapper
{
    /// <summary>
    /// Maps a given exception to a corresponding <see cref="ApiErrorItem"/>.
    /// </summary>
    /// <param name="exception">The exception to map.</param>
    /// <returns>The mapped <see cref="ApiErrorItem"/>.</returns>
    public static ApiErrorItem Map(Exception exception)
    {
        return exception switch
        {
            InvalidCredentialsException ex => new ApiErrorItem(ApiErrorCode.InvalidCredentials, ex.Message),
            PasswordPolicyViolationException ex => new ApiErrorItem(ex.ErrorCode, ex.Message),
            UserNotFoundException ex => new ApiErrorItem(ApiErrorCode.UserNotFound, ex.Message),
            DirectoryUnavailableException ex => new ApiErrorItem(ApiErrorCode.LdapProblem, ex.Message),
            _ => new ApiErrorItem(ApiErrorCode.Generic, exception.Message)
        };
    }
}
