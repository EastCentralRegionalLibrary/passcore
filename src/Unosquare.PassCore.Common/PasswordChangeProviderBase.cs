using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Base class for password change providers.
/// </summary>
public abstract class PasswordChangeProviderBase : IPasswordChangeProvider
{
    protected PasswordChangeProviderBase(ILogger logger, IEnumerable<IPasswordPolicy> policies)
    {
        Logger = logger;
        Policies = policies;
    }

    protected ILogger Logger { get; }

    protected IEnumerable<IPasswordPolicy> Policies { get; }

    /// <inheritdoc />
    [Obsolete("Use ChangePasswordAsync instead.")]
    public virtual async Task<ApiErrorItem?> PerformPasswordChangeAsync(
        string username,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default)
    {
        var result = await ChangePasswordAsync(
            new PasswordChangeContext
            {
                Username = username,
                CurrentPassword = currentPassword,
                NewPassword = newPassword
            },
            cancellationToken);

        return result.Error;
    }

    /// <inheritdoc />
    public virtual async Task<PasswordChangeResult> ChangePasswordAsync(
        PasswordChangeContext context,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var operationId = Guid.NewGuid();
        using var scope = Logger.BeginScope(new Dictionary<string, object> { ["OperationId"] = operationId });

        Logger.LogInformation("Starting password change operation for user: {Username}", context.Username);

        try
        {
            ValidateContext(context);

            foreach (var policy in Policies)
            {
                policy.Validate(context, this);
            }

            await ChangePasswordCoreAsync(context, cancellationToken);

            Logger.LogInformation("Password successfully changed for user: {Username}", context.Username);
            return PasswordChangeResult.SuccessResult();
        }
        catch (PasswordChangeException ex)
        {
            Logger.LogWarning(ex, "Password change failed for user {Username}: {Message}", context.Username, ex.Message);
            return PasswordChangeResult.Failure(ApiErrorMapper.Map(ex));
        }
        catch (Exception ex)
        {
            Logger.LogError(ex, "Unexpected error during password change for user {Username}", context.Username);
            return PasswordChangeResult.Failure(ApiErrorMapper.Map(ex));
        }
    }

    /// <summary>
    /// Core implementation of the password change logic.
    /// </summary>
    /// <param name="context">The password change context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the operation.</returns>
    protected abstract Task ChangePasswordCoreAsync(PasswordChangeContext context, CancellationToken cancellationToken);

    private static void ValidateContext(PasswordChangeContext context)
    {
        if (string.IsNullOrWhiteSpace(context.Username))
            throw new InvalidCredentialsException("Username is required");
        if (string.IsNullOrWhiteSpace(context.CurrentPassword))
            throw new InvalidCredentialsException("Current password is required");
        if (string.IsNullOrWhiteSpace(context.NewPassword))
            throw new InvalidCredentialsException("New password is required");
    }
}
