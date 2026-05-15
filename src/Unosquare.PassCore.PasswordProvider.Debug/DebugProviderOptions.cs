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
}
