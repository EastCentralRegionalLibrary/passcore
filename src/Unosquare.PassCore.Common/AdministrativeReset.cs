using System;
using Microsoft.Extensions.Logging;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Shared decision gate and logging for the administrative password-reset
/// fallback (<see cref="IAppSettings.AllowAdministrativeReset"/>), kept in one
/// place so both providers apply identical semantics and produce an identical
/// log shape.
///
/// The fallback may fire only when ALL of the following hold:
/// <list type="bullet">
/// <item>the option is enabled (default off);</item>
/// <item>the user's <b>current</b> credentials were successfully verified
/// earlier in the same request — an administrative reset without proof of the
/// current password would be an account-takeover primitive;</item>
/// <item>the failure is one an administrative reset can actually cure: a
/// new-password policy rejection (history, minimum age — which resets bypass —
/// or length/complexity) or a cannot-change-password restriction, i.e. a
/// <see cref="PasswordPolicyViolationException"/> from the shared translator.
/// Wrong-credential and infrastructure failures are never rescued.</item>
/// </list>
/// </summary>
public static class AdministrativeReset
{
    private static readonly Action<ILogger, string?, string, string, Exception?> LogPerformedDefinition =
        LoggerMessage.Define<string?, string, string>(
            LogLevel.Warning,
            new EventId(110, "AdministrativeResetPerformed"),
            "[{CorrelationId}] ADMINISTRATIVE PASSWORD RESET performed for user {Username}: the " +
            "user-context password change failed ({OriginalFailure}) and AllowAdministrativeReset " +
            "is enabled, so the new password was set with the service account. Password history " +
            "and minimum-age policies were bypassed for this change.");

    /// <summary>
    /// Decides whether a failed user-context password change may fall back to
    /// an administrative reset. Never throws.
    /// </summary>
    /// <param name="allowAdministrativeReset">The configured option value.</param>
    /// <param name="currentCredentialsVerified">
    /// Whether the user's current credentials were successfully verified
    /// earlier in this request. Callers must pass a value derived from the
    /// actual verification step, never a constant <see langword="true"/> that
    /// precedes it.
    /// </param>
    /// <param name="translatedFailure">The change failure, already routed through
    /// <see cref="DirectoryErrorTranslator"/>.</param>
    /// <returns><see langword="true"/> when the reset may be attempted.</returns>
    public static bool ShouldAttempt(
        bool allowAdministrativeReset,
        bool currentCredentialsVerified,
        Exception? translatedFailure) =>
        allowAdministrativeReset
        && currentCredentialsVerified
        && translatedFailure is PasswordPolicyViolationException;

    /// <summary>
    /// Emits the loud, uniform Warning both providers log immediately after a
    /// successful administrative reset: correlation ID, username, the original
    /// translated failure, and an explicit statement that a reset was performed
    /// and what it bypassed.
    /// </summary>
    /// <param name="logger">The provider's logger.</param>
    /// <param name="correlationId">The request correlation ID.</param>
    /// <param name="username">The account whose password was reset.</param>
    /// <param name="originalFailure">The translated failure that triggered the fallback.</param>
    public static void LogPerformed(
        ILogger logger,
        string? correlationId,
        string username,
        Exception originalFailure)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(originalFailure);

        LogPerformedDefinition(logger, correlationId ?? "n/a", username, originalFailure.Message, originalFailure);
    }
}
