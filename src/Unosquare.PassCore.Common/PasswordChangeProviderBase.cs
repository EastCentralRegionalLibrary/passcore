using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;

namespace Unosquare.PassCore.Common;

public abstract class PasswordChangeProviderBase : IPasswordChangeProvider
{
    protected ILogger Logger { get; }
    protected IEnumerable<IPasswordPolicy> Policies { get; }

    protected PasswordChangeProviderBase(ILogger logger, IEnumerable<IPasswordPolicy>? policies = null)
    {
        Logger = logger;
        Policies = policies ?? Array.Empty<IPasswordPolicy>();
    }

    public virtual async Task<PasswordChangeResult> ChangePasswordAsync(PasswordChangeContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var operationId = Guid.NewGuid().ToString();
        Logger.LogInformation("[{OperationId}] Starting password change for user: {Username}", operationId, context.Username);

        try
        {
            ValidateContext(context);

            foreach (var policy in Policies)
            {
                await policy.ValidateAsync(context, this);
            }

            await ChangePasswordCore(context, cancellationToken);

            Logger.LogInformation("[{OperationId}] Password changed successfully for user: {Username}", operationId, context.Username);
            return PasswordChangeResult.Success();
        }
        catch (OperationCanceledException ex)
        {
            Logger.LogWarning(ex, "[{OperationId}] Password change canceled for user: {Username}", operationId, context.Username);
            throw;
        }
        catch (Exception ex)
        {
            Logger.LogWarning(ex, "[{OperationId}] Password change failed for user: {Username}", operationId, context.Username);
            return PasswordChangeResult.Fail(ApiErrorMapper.Map(ex));
        }
    }

    protected virtual void ValidateContext(PasswordChangeContext context)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (string.IsNullOrWhiteSpace(context.Username))
            throw new InvalidCredentialsException("Username is required");
        if (string.IsNullOrWhiteSpace(context.CurrentPassword))
            throw new InvalidCredentialsException("Current password is required");
        if (string.IsNullOrWhiteSpace(context.NewPassword))
            throw new InvalidCredentialsException("New password is required");
    }

    protected abstract Task ChangePasswordCore(PasswordChangeContext context, CancellationToken cancellationToken);

    // Legacy method for backward compatibility
    [Obsolete("Use ChangePasswordAsync instead")]
    public virtual async Task<ApiErrorItem?> PerformPasswordChangeAsync(string username, string currentPassword, string newPassword, CancellationToken cancellationToken = default)
    {
        var result = await ChangePasswordAsync(new PasswordChangeContext(username, currentPassword, newPassword, new ClientSettings()), cancellationToken);
        return result.Error;
    }

    public int MeasureNewPasswordDistance(string currentPassword, string newPassword)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);
        ArgumentNullException.ThrowIfNull(newPassword);

        var n = currentPassword.Length;
        var m = newPassword.Length;

        if (n == 0) return m;
        if (m == 0) return n;

        var d = new int[n + 1, m + 1];

        for (int i = 0; i <= n; d[i, 0] = i++) { }
        for (int j = 0; j <= m; d[0, j] = j++) { }

        for (int i = 1; i <= n; i++)
        {
            for (int j = 1; j <= m; j++)
            {
                int cost = (newPassword[j - 1] == currentPassword[i - 1]) ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
            }
        }

        return d[n, m];
    }
}
