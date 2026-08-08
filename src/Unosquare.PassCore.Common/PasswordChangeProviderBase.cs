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
public abstract class PasswordChangeProviderBase : IPasswordChangeProvider, IDisclosurePosture, IPasswordLengthRequirement
{
    /// <inheritdoc />
    public virtual ErrorDisclosureMode ErrorDisclosureMode => ErrorDisclosureMode.Hardened;

    /// <summary>Gets the logger for the provider.</summary>
    protected ILogger Logger { get; }

    /// <summary>Gets the registered password policies.</summary>
    protected IEnumerable<IPasswordPolicy> Policies { get; }

    /// <summary>Gets the client settings used by the provider.</summary>
    protected ClientSettings ClientSettings { get; }

    // Per INSTANCE, deliberately not static. The value is domain-wide, but a
    // process could in principle hold two providers pointed at two directories,
    // and a static cache would hand one of them the other's policy. Sharing
    // would save one lookup per five minutes and risk advertising the wrong
    // minimum; the trade is not close.
    private readonly CachedDomainMinimumLength _minimumLength = new();

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordChangeProviderBase"/> class.
    /// </summary>
    /// <param name="logger">The logger instance.</param>
    /// <param name="clientSettings">The client settings.</param>
    /// <param name="policies">The collection of password policies.</param>
    protected PasswordChangeProviderBase(
        ILogger logger,
        ClientSettings? clientSettings = null,
        IEnumerable<IPasswordPolicy>? policies = null)
    {
        Logger = logger;
        ClientSettings = clientSettings ?? new ClientSettings();
        Policies = policies ?? Array.Empty<IPasswordPolicy>();
    }

    // EventId allocation across the solution. Provider selection is build-time,
    // so an AD-built and an LDAP-built instance never share a process — but their
    // logs are routinely aggregated together, so an ID must mean one thing
    // everywhere. Ranges, and the next free number in each:
    //
    //   1-9      this base class (password-change and policy lifecycle)   next: 10
    //   100-109  provider-specific events                                  next: 110
    //            LDAP: 100, 101, 102, 104, 106, 107.  AD: 103, 108, 109.
    //            105 is retired: it logged a group-enumeration failure as an
    //            expected Debug-level fallback, which no longer exists. Such a
    //            failure now leaves membership undetermined and is reported via
    //            ServiceAccountFailure (111). Retired, not free -- do not reuse.
    //   110-119  shared helpers (AdministrativeReset, ServiceAccountFailure,
    //            DomainPasswordPolicy), then provider-specific events that
    //            would have belonged in the range above had it not been full:
    //            LDAP GroupNotSecurityEnabled (113), LDAP GroupTypeUnreadable
    //            (114), AD LdapsWriteRequired (115),
    //            AD SealedBindSkippedForLdapsPort (116),
    //            AD PasswordWriteOverLdaps (118),
    //            AD LdapsWriteBindFailed (119).
    //            117 is retired: it announced at startup that no password write
    //            could succeed in the explicit-bind, non-domain-joined
    //            combination and that RPC/SMB reachability was the remedy. The
    //            write was subsequently made to bind over LDAPS, which works in
    //            exactly that combination, so the claim is false and the remedy
    //            was the wrong one. Retired, not free -- do not reuse.
    //            Numbering continues here rather than reusing a retired ID.
    //                                                                     next: 120
    //   120-121  identity-type classification warnings, added once
    //            UserIdentityTypeClassifier moved the AD provider's alias table into
    //            Common: AD UnrecognizedIdentityType (120), AD IdentityTypeNotWebUsable
    //            (121).
    //                                                                     next: 122
    //   200-202  Web layer (PasswordController)                            next: 203
    //   300-304  PwnedPasswordsSearch                                      next: 305
    //
    // Take the next free number in the appropriate range; never reuse or
    // renumber one that has shipped.
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
        ChangePasswordAsync(new PasswordChangeContext(
            username,
            currentPassword,
            newPassword,
            ClientSettings,
            correlationId: Guid.NewGuid().ToString("N")[..8]));

    /// <summary>
    /// Performs the core asynchronous password change, running all policies and mapping exceptions.
    /// </summary>
    /// <param name="context">The password change request context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A <see cref="PasswordChangeResult"/> indicating the outcome of the operation.</returns>
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
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            LogPasswordChangeFailed(Logger, context.CorrelationId, context.Username, ex);

            // Never serialize raw exception text: the Generic code renders its
            // message verbatim in the UI. The correlation ID ties the clean
            // surface text back to the full detail logged above.
            return PasswordChangeResult.Fail(new ApiErrorItem(
                ApiErrorCode.Generic,
                $"An unexpected error occurred (ref: {context.CorrelationId ?? "n/a"})"));
        }
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>Cached with a short time-to-live, because this runs on every POST —
    /// before the caller has proved anything — and the lookup behind it costs a
    /// bind plus a search or two against a value that is domain-wide and changes
    /// about as often as a group policy edit. Only a directory-sourced value is
    /// cached, so a failing lookup keeps re-attempting and keeps logging its
    /// warning rather than having it suppressed for the whole TTL.</para>
    /// <para>Both shipped directory providers had an identical copy of this. What
    /// genuinely differs between them is <see cref="ReadMinPwdLength"/>, so that is
    /// the only part they still supply.</para>
    /// </remarks>
    public Task<int> GetMinimumLengthAsync() =>
        Task.FromResult(_minimumLength.Resolve(Logger, ReadMinPwdLength));

    /// <summary>
    /// Reads the directory's minimum password length, or returns
    /// <see langword="null"/> when this provider has no such value to read.
    /// </summary>
    /// <remarks>
    /// <para>May throw. A throwing lookup and a <see langword="null"/> one are the
    /// same case as far as callers are concerned: <see cref="DomainPasswordPolicy"/>
    /// logs the condition at Warning and advertises
    /// <see cref="DomainPasswordPolicy.DefaultMinimumLength"/>. Neither reaches the
    /// end user, and neither is cached.</para>
    /// <para>Because <see langword="null"/> is a handled answer rather than a
    /// failure, a provider that cannot read a domain policy does not need to opt out
    /// of <see cref="IPasswordLengthRequirement"/> — which is why the base can
    /// implement it for everyone.</para>
    /// </remarks>
    /// <returns>The directory's minimum password length, or <see langword="null"/>.</returns>
    protected abstract int? ReadMinPwdLength();

    /// <summary>
    /// Validates that the context contains required fields.
    /// </summary>
    /// <param name="context">The context to validate.</param>
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

    /// <summary>
    /// Executes the directory-specific password change logic.
    /// </summary>
    /// <param name="context">The password change request context.</param>
    /// <param name="cancellationToken">The cancellation token.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    protected abstract Task ChangePasswordCore(PasswordChangeContext context, CancellationToken cancellationToken);
}
