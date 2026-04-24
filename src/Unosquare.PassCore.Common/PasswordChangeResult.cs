namespace Unosquare.PassCore.Common;

public class PasswordChangeResult
{
    public bool IsSuccess { get; private set; }
    public ApiErrorItem? Error { get; private set; }

    public static PasswordChangeResult Success() => new() { IsSuccess = true };
    public static PasswordChangeResult Fail(ApiErrorItem error) => new() { IsSuccess = false, Error = error };
    public static PasswordChangeResult Fail(ApiErrorCode errorCode, string? message = null) => Fail(new ApiErrorItem(errorCode, message));
}
