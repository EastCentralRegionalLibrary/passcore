using System.Collections.Generic;
using Unosquare.PassCore.Common;

namespace Unosquare.PassCore.PasswordProvider.Debug;

#if DEBUG
/// <summary>
/// Options for the debug password change provider.
/// </summary>
public class DebugProviderOptions
{
    /// <summary>
    /// Gets or sets a value indicating whether to enable pwned password checks.
    /// </summary>
    public bool EnablePwnedCheck { get; set; }

    /// <summary>
    /// Gets or sets the mapping of usernames to specific API error codes.
    /// </summary>
    public Dictionary<string, ApiErrorCode> ForcedErrors { get; set; } = new();

    /// <summary>
    /// Gets or sets the latency to simulate in milliseconds.
    /// </summary>
    public int SimulateLatencyMs { get; set; }

    /// <summary>
    /// Gets or sets the default result if no forced error is matched.
    /// </summary>
    public ApiErrorCode? DefaultErrorCode { get; set; }
}
#endif
