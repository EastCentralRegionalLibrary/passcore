using System;
using System.Threading;
using System.Threading.Tasks;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Represents a interface for a password change provider.
/// </summary>
public interface IPasswordChangeProvider
{
    /// <summary>
    /// Performs the password change using the credentials provided.
    /// </summary>
    /// <param name="username">The username.</param>
    /// <param name="currentPassword">The current password.</param>
    /// <param name="newPassword">The new password.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The API error item or null if the change password operation was successful.</returns>
    [Obsolete("Use ChangePasswordAsync instead")]
    Task<ApiErrorItem?> PerformPasswordChangeAsync(string username, string currentPassword, string newPassword, CancellationToken cancellationToken = default);

    /// <summary>
    /// Performs the password change using the credentials provided in the context.
    /// </summary>
    /// <param name="context">The password change context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>The password change result.</returns>
    Task<PasswordChangeResult> ChangePasswordAsync(PasswordChangeContext context, CancellationToken cancellationToken = default);

}
