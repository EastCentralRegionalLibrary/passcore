namespace Unosquare.PassCore.Common;

/// <summary>
/// Represents the result of a password change operation.
/// </summary>
public class PasswordChangeResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordChangeResult"/> class.
    /// </summary>
    /// <param name="success">if set to <c>true</c> [success].</param>
    /// <param name="error">The error.</param>
    public PasswordChangeResult(bool success, ApiErrorItem? error = null)
    {
        Success = success;
        Error = error;
    }

    /// <summary>
    /// Gets a value indicating whether this <see cref="PasswordChangeResult"/> is success.
    /// </summary>
    public bool Success { get; }

    /// <summary>
    /// Gets the error.
    /// </summary>
    public ApiErrorItem? Error { get; }

    /// <summary>
    /// Creates a success result.
    /// </summary>
    /// <returns>A success <see cref="PasswordChangeResult"/>.</returns>
    public static PasswordChangeResult SuccessResult() => new(true);

    /// <summary>
    /// Creates a failure result.
    /// </summary>
    /// <param name="error">The error.</param>
    /// <returns>A failure <see cref="PasswordChangeResult"/>.</returns>
    public static PasswordChangeResult Failure(ApiErrorItem error) => new(false, error);
}
