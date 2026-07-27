namespace Unosquare.PassCore.Common;

/// <summary>
/// Defines a provider that exposes an error disclosure posture.
/// </summary>
public interface IDisclosurePosture
{
    /// <summary>
    /// Gets the configured error-disclosure posture.
    /// </summary>
    ErrorDisclosureMode ErrorDisclosureMode { get; }
}
