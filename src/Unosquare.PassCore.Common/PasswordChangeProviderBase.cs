using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Base class for password change providers. Centralizes logging, policy evaluation,
/// validation and exception-to-error mapping so concrete providers only need to
/// implement <see cref="ChangePasswordCore"/>.
/// </summary>
public abstract class PasswordChangeProviderBase : IPasswordChangeProvider
{
    protected ILogger Logger { get; }
    protected IEnumerable<IPasswordPolicy> Policies { get; }
    protected ClientSettings ClientSettings { get; }

    protected PasswordChangeProviderBase(
        ILogger logger,
        ClientSettings? clientSettings = null,
        IEnumerable<IPasswordPolicy>? policies = null)
    {
        Logger = logger;
        ClientSettings = clientSettings ?? new ClientSettings();
        Policies = policies ?? Array.Empty<IPasswordPolicy>();
    }

    private static readonly Action<ILogger, string?, string, Exception?> LogStartingPasswordChange =
        LoggerMessage.Define<string?, string>(
            LogLevel.Information,
            new EventId(1, nameof(LogStartingPasswordChange)),
            "[{CorrelationId}] Starting password change for user: {Username}");

    private static readonly Action<ILogger, string?, string, Exception?> LogPasswordChangedSuccessfully =
        LoggerMessage.Define<string?, string>(
            LogLevel.Information,
            new EventId(2, nameof(LogPasswordChangedSuccessfully)),
            "[{CorrelationId}] Password changed successfully for user: {Username}");

    private static readonly Action<ILogger, string?, string, Exception?> LogPasswordChangeCanceled =
        LoggerMessage.Define<string?, string>(
            LogLevel.Warning,
            new EventId(3, nameof(LogPasswordChangeCanceled)),
            "[{CorrelationId}] Password change canceled for user: {Username}");

    private static readonly Action<ILogger, string?, string, Exception?> LogPasswordChangeFailed =
        LoggerMessage.Define<string?, string>(
            LogLevel.Warning,
            new EventId(4, nameof(LogPasswordChangeFailed)),
            "[{CorrelationId}] Password change failed for user: {Username}");

    private static readonly Action<ILogger, string?, string, string, Exception?> LogPolicyEvaluationStart =
        LoggerMessage.Define<string?, string, string>(
            LogLevel.Debug,
            new EventId(5, nameof(LogPolicyEvaluationStart)),
            "[{CorrelationId}] Starting policy evaluation: {PolicyName} for user: {Username}");

    private static readonly Action<ILogger, string?, string, string, Exception?> LogPolicyEvaluationSuccess =
        LoggerMessage.Define<string?, string, string>(
            LogLevel.Debug,
            new EventId(6, nameof(LogPolicyEvaluationSuccess)),
            "[{CorrelationId}] Policy evaluation success: {PolicyName} for user: {Username}");

    private static readonly Action<ILogger, string?, string, string, Exception?> LogPolicyEvaluationFailed =
        LoggerMessage.Define<string?, string, string>(
            LogLevel.Warning,
            new EventId(7, nameof(LogPolicyEvaluationFailed)),
            "[{CorrelationId}] Policy evaluation failed: {PolicyName} for user: {Username}");

    private static readonly Action<ILogger, string?, string, Exception?> LogProviderExecutionStart =
        LoggerMessage.Define<string?, string>(
            LogLevel.Debug,
            new EventId(8, nameof(LogProviderExecutionStart)),
            "[{CorrelationId}] Starting provider execution for user: {Username}");

    private static readonly Action<ILogger, string?, string, Exception?> LogProviderExecutionSuccess =
        LoggerMessage.Define<string?, string>(
            LogLevel.Debug,
            new EventId(9, nameof(LogProviderExecutionSuccess)),
            "[{CorrelationId}] Provider execution success for user: {Username}");

    /// <inheritdoc />
    public virtual Task<PasswordChangeResult> PerformPasswordChangeAsync(
        string username,
        string currentPassword,
        string newPassword) =>
        ChangePasswordAsync(new PasswordChangeContext(username, currentPassword, newPassword, ClientSettings));

    protected virtual async Task<PasswordChangeResult> ChangePasswordAsync(PasswordChangeContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        LogStartingPasswordChange(Logger, context.CorrelationId, context.Username, null);

        try
        {
            ValidateContext(context);

            foreach (var policy in Policies)
            {
                var policyName = policy.GetType().Name;
                LogPolicyEvaluationStart(Logger, context.CorrelationId, policyName, context.Username, null);
                try
                {
                    await policy.ValidateAsync(context, this);
                    LogPolicyEvaluationSuccess(Logger, context.CorrelationId, policyName, context.Username, null);
                }
                catch (Exception ex)
                {
                    LogPolicyEvaluationFailed(Logger, context.CorrelationId, policyName, context.Username, ex);
                    throw;
                }
            }

            LogProviderExecutionStart(Logger, context.CorrelationId, context.Username, null);
            await ChangePasswordCore(context, cancellationToken);
            LogProviderExecutionSuccess(Logger, context.CorrelationId, context.Username, null);

            LogPasswordChangedSuccessfully(Logger, context.CorrelationId, context.Username, null);
            return PasswordChangeResult.Success();
        }
        catch (OperationCanceledException ex)
        {
            LogPasswordChangeCanceled(Logger, context.CorrelationId, context.Username, ex);
            throw;
        }
        catch (PasswordChangeException ex)
        {
            LogPasswordChangeFailed(Logger, context.CorrelationId, context.Username, ex);
            return PasswordChangeResult.Fail(ApiErrorMapper.Map(ex));
        }
        catch (Exception ex)
        {
            LogPasswordChangeFailed(Logger, context.CorrelationId, context.Username, ex);
            return PasswordChangeResult.Fail(new ApiErrorItem(ApiErrorCode.Generic, ex.Message));
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
}
