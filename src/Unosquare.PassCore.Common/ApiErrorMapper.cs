using System;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common;

public static class ApiErrorMapper
{
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
