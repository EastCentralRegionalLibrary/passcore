using System.Collections.Generic;
using System.Linq;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Represents the result of a password change attempt.
/// </summary>
public class PasswordChangeResult
{
    /// <summary>Gets a value indicating whether the password change was successful.</summary>
    public bool IsSuccessful { get; private set; }

    /// <summary>Gets the collection of API error items when the change failed.</summary>
    public IEnumerable<ApiErrorItem> Errors { get; private set; } = Enumerable.Empty<ApiErrorItem>();

    /// <summary>Creates a successful password change result.</summary>
    public static PasswordChangeResult Success() => new() { IsSuccessful = true };

    /// <summary>Creates a failed password change result with the specified error items.</summary>
    public static PasswordChangeResult Failure(IEnumerable<ApiErrorItem> errors) => new() { IsSuccessful = false, Errors = errors };

    /// <summary>Creates a failed password change result with a single error item.</summary>
    public static PasswordChangeResult Fail(ApiErrorItem error) => Failure(new[] { error });

    /// <summary>Creates a failed password change result with the specified error code and message.</summary>
    public static PasswordChangeResult Fail(ApiErrorCode errorCode, string? message = null) => Fail(new ApiErrorItem(errorCode, message));
}
