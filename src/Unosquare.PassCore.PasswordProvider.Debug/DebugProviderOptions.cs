using System;
using System.Collections.Generic;
using Unosquare.PassCore.Common;

namespace Unosquare.PassCore.PasswordProvider.Debug;

/// <summary>
/// Options that configure the behavior of <see cref="DebugPasswordChangeProvider"/>.
/// </summary>
public class DebugProviderOptions
{
    /// <summary>
    /// Maps usernames (local part, case-insensitive) to specific API error codes
    /// that the provider should raise instead of succeeding.
    /// </summary>
    public Dictionary<string, ApiErrorCode> ForcedErrors { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// Artificial latency, in milliseconds, applied before evaluating the request.
    /// Useful for exercising UI loading states.
    /// </summary>
    public int SimulateLatencyMs { get; set; }

    /// <summary>
    /// Optional fallback error code returned when neither <see cref="ForcedErrors"/>
    /// nor the legacy username-based mapping matches.
    /// </summary>
    public ApiErrorCode? DefaultErrorCode { get; set; }

    /// <summary>
    /// The minimum password length this provider reports, standing in for the
    /// domain policy a directory provider would read.
    /// </summary>
    /// <remarks>
    /// <para>Exists so <c>LengthPasswordPolicy</c> can actually be exercised in
    /// development. This provider previously reported no minimum at all, so the
    /// policy silently did nothing whenever it was selected — a length rule that
    /// cannot be triggered is a length rule nobody can see is broken.</para>
    /// <para>A real value rather than "unavailable" for a second reason: reporting
    /// nothing would take the shared fallback path, which logs an
    /// operator-actionable Warning on every cache expiry. That warning is correct
    /// for a directory provider that cannot reach its domain controller and is pure
    /// noise for a provider that has no domain to reach.</para>
    /// </remarks>
    public int MinimumLength { get; set; } = 8;
}
