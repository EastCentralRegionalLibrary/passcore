using System.Collections.Generic;
using System.Linq;

namespace Unosquare.PassCore.Common;

public class PasswordChangeResult
{
    public bool IsSuccessful { get; private set; }
    public IEnumerable<ApiErrorItem> Errors { get; private set; } = Enumerable.Empty<ApiErrorItem>();

    public static PasswordChangeResult Success() => new() { IsSuccessful = true };
    public static PasswordChangeResult Failure(IEnumerable<ApiErrorItem> errors) => new() { IsSuccessful = false, Errors = errors };

    public static PasswordChangeResult Fail(ApiErrorItem error) => Failure(new[] { error });
    public static PasswordChangeResult Fail(ApiErrorCode errorCode, string? message = null) => Fail(new ApiErrorItem(errorCode, message));
}
