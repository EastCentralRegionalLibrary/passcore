using System;
using Microsoft.Extensions.Logging;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Shared decision gate and logging for the administrative password-reset
/// fallback (<see cref="IAppSettings.AllowAdministrativeReset"/>), kept in one
/// place so both providers apply identical semantics and produce an identical
/// log shape. This is the only place rescue eligibility is decided; pre-flight
/// callers pass a synthesized <see cref="DirectoryFailureClass"/> rather than
/// implementing their own check.
///
/// The fallback may fire only when ALL of the following hold:
/// <list type="bullet">
/// <item>the option is enabled (default off);</item>
/// <item>the user's <b>current</b> credentials were successfully verified
/// earlier in the same request — an administrative reset without proof of the
/// current password would be an account-takeover primitive;</item>
/// <item>the failure class is exactly
/// <see cref="DirectoryFailureClass.ChangeNotPermitted"/> — the account is
/// flagged so the user cannot change their own password. Intentional password
/// policy (length, complexity, history, minimum age —
/// <see cref="DirectoryFailureClass.NewPasswordPolicy"/>) is always honored;
/// account-state conditions (locked, disabled, hours —
/// <see cref="DirectoryFailureClass.AccountState"/>) are never rescued in any
/// disclosure mode (a reset would not cure them, and in informative mode they
/// share an exception shape with cannot-change, which is why the decision is
/// class-based rather than exception-type-based); infrastructure failures
/// (<see cref="DirectoryFailureClass.Infrastructure"/>) are never rescued or
/// probed.</item>
/// </list>
/// </summary>
public static class AdministrativeReset
{
    private static readonly Action<ILogger, string?, string, string, Exception?> LogPerformedDefinition =
        LoggerMessage.Define<string?, string, string>(
            LogLevel.Warning,
            new EventId(110, "AdministrativeResetPerformed"),
            "[{CorrelationId}] ADMINISTRATIVE PASSWORD RESET performed for user {Username}: the " +
            "account is flagged so the user cannot change their own password ({OriginalFailure}) " +
            "and AllowAdministrativeReset is enabled, so the new password was set with the " +
            "service account. Note that administrative resets are not subject to password " +
            "history or minimum-age policy.");

    /// <summary>
    /// Decides whether a failed or blocked user-context password change may
    /// fall back to an administrative reset. Never throws. Returns
    /// <see langword="true"/> only for
    /// <see cref="DirectoryFailureClass.ChangeNotPermitted"/> with the option
    /// enabled and credentials verified.
    /// </summary>
    /// <param name="allowAdministrativeReset">The configured option value.</param>
    /// <param name="currentCredentialsVerified">
    /// Whether the user's current credentials were successfully verified
    /// earlier in this request. Callers must pass a value derived from the
    /// actual verification step, never a constant <see langword="true"/> that
    /// precedes it.
    /// </param>
    /// <param name="failureClass">The classification of the failure or blocking
    /// condition, from <see cref="DirectoryErrorTranslator"/> or synthesized by
    /// a pre-flight check that detected the cannot-change flag directly.</param>
    /// <returns><see langword="true"/> when the reset may be attempted.</returns>
    public static bool ShouldAttempt(
        bool allowAdministrativeReset,
        bool currentCredentialsVerified,
        DirectoryFailureClass failureClass) =>
        allowAdministrativeReset
        && currentCredentialsVerified
        && failureClass == DirectoryFailureClass.ChangeNotPermitted;

    /// <summary>
    /// Emits the loud, uniform Warning both providers log immediately after a
    /// successful administrative reset: correlation ID, username, the original
    /// translated failure, and an explicit statement that a reset was performed
    /// and what that implies.
    /// </summary>
    /// <param name="logger">The provider's logger.</param>
    /// <param name="correlationId">The request correlation ID.</param>
    /// <param name="username">The account whose password was reset.</param>
    /// <param name="originalFailure">The translated failure or blocking condition that triggered the fallback.</param>
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
