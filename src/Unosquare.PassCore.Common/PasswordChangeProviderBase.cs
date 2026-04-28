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
    private static readonly Action<ILogger, string, Exception?> _logStartingPasswordChange =
        LoggerMessage.Define<string>(LogLevel.Information, new EventId(1, nameof(ChangePasswordAsync)), "Starting password change for user: {Username}");

    private static readonly Action<ILogger, string, string, Exception?> _logPolicyEvaluating =
        LoggerMessage.Define<string, string>(LogLevel.Debug, new EventId(2, nameof(ChangePasswordAsync)), "Evaluating policy: {PolicyName} for user: {Username}");

    private static readonly Action<ILogger, string, string, Exception?> _logPolicySuccess =
        LoggerMessage.Define<string, string>(LogLevel.Debug, new EventId(3, nameof(ChangePasswordAsync)), "Policy: {PolicyName} passed for user: {Username}");

    private static readonly Action<ILogger, string, string, string, Exception?> _logPolicyFailure =
        LoggerMessage.Define<string, string, string>(LogLevel.Warning, new EventId(4, nameof(ChangePasswordAsync)), "Policy: {PolicyName} failed for user: {Username}. Error: {ErrorMessage}");

    private static readonly Action<ILogger, string, Exception?> _logPasswordChangedSuccessfully =
        LoggerMessage.Define<string>(LogLevel.Information, new EventId(5, nameof(ChangePasswordAsync)), "Password changed successfully for user: {Username}");

    private static readonly Action<ILogger, string, Exception?> _logPasswordChangeCanceled =
        LoggerMessage.Define<string>(LogLevel.Warning, new EventId(6, nameof(ChangePasswordAsync)), "Password change canceled for user: {Username}");

    private static readonly Action<ILogger, string, string, Exception?> _logPasswordChangeFailed =
        LoggerMessage.Define<string, string>(LogLevel.Warning, new EventId(7, nameof(ChangePasswordAsync)), "Password change failed for user: {Username}. Error: {ErrorMessage}");

    protected ILogger Logger { get; }
    protected IEnumerable<IPasswordPolicy> Policies { get; }

    protected PasswordChangeProviderBase(ILogger logger, IEnumerable<IPasswordPolicy>? policies = null)
    {
        Logger = logger ?? throw new ArgumentNullException(nameof(logger));
        Policies = policies ?? Array.Empty<IPasswordPolicy>();
    }

    public virtual async Task<PasswordChangeResult> ChangePasswordAsync(PasswordChangeContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        _logStartingPasswordChange(Logger, context.Username, null);

        try
        {
            ValidateContext(context);

            foreach (var policy in Policies)
            {
                var policyName = policy.GetType().Name;
                _logPolicyEvaluating(Logger, policyName, context.Username, null);

                try
                {
                    await policy.ValidateAsync(context, this);
                    _logPolicySuccess(Logger, policyName, context.Username, null);
                }
                catch (PasswordPolicyViolationException ex)
                {
                    _logPolicyFailure(Logger, policyName, context.Username, ex.Message, null);
                    throw;
                }
            }

            await ChangePasswordCore(context, cancellationToken);

            _logPasswordChangedSuccessfully(Logger, context.Username, null);
            return PasswordChangeResult.Success();
        }
        catch (OperationCanceledException ex)
        {
            _logPasswordChangeCanceled(Logger, context.Username, ex);
            throw;
        }
        catch (PasswordChangeException ex)
        {
            _logPasswordChangeFailed(Logger, context.Username, ex.Message, ex);
            return PasswordChangeResult.Fail(ApiErrorMapper.Map(ex));
        }
        catch (Exception ex)
        {
            _logPasswordChangeFailed(Logger, context.Username, ex.Message, ex);
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
}
