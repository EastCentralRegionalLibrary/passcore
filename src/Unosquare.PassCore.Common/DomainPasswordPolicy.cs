using System;
using Microsoft.Extensions.Logging;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Shared, transport-agnostic resolution of the domain's minimum password
/// length, with the fallback decision made in one testable place. A provider
/// supplies the directory-specific lookup; this helper decides what to do when
/// it fails or returns nothing — crucially, it does so without silence.
/// </summary>
/// <remarks>
/// When the lookup fails (unreachable DC, service account cannot read
/// <c>minPwdLength</c>) or the value is absent, PassCore would otherwise
/// advertise a minimum length <b>weaker</b> than the domain actually enforces:
/// the user passes client-side validation, submits, and the directory rejects
/// the password as too short with nothing in the logs explaining why. The
/// fallback value is kept at the long-standing default so a working deployment
/// is unaffected, but the failure is logged at Warning as an operator-actionable
/// condition.
/// </remarks>
public static class DomainPasswordPolicy
{
    /// <summary>
    /// The minimum password length advertised when the domain policy cannot be
    /// read. Historically the default and kept to avoid changing behavior for
    /// deployments where the lookup works; the log makes the fallback visible
    /// when it does not.
    /// </summary>
    public const int DefaultMinimumLength = 6;

    private static readonly Action<ILogger, int, Exception?> LogLookupFailed =
        LoggerMessage.Define<int>(
            LogLevel.Warning,
            new EventId(112, "MinimumPasswordLengthLookupFailed"),
            "Could not read the domain minimum password length (minPwdLength); advertising the " +
            "fallback of {FallbackLength}. If the domain enforces a longer minimum, users will " +
            "pass client-side length validation and then be rejected by the directory. Check " +
            "connectivity to the domain controller and that the service account can read the " +
            "domain password policy.");

    /// <summary>
    /// Resolves the minimum password length: returns the looked-up value when
    /// present, otherwise logs at Warning and returns <paramref name="fallback"/>.
    /// Never throws — a lookup failure is turned into the logged fallback.
    /// </summary>
    /// <param name="logger">The provider's logger.</param>
    /// <param name="lookup">The directory-specific lookup; returns the domain's
    /// minimum length, or <see langword="null"/> when it is unavailable. May throw,
    /// in which case the exception is logged and the fallback is returned.</param>
    /// <param name="fallback">The value to advertise when the lookup yields nothing.</param>
    /// <returns>The resolved minimum length.</returns>
    public static int ResolveMinimumLength(
        ILogger logger,
        Func<int?> lookup,
        int fallback = DefaultMinimumLength) =>
        ResolveMinimumLength(logger, lookup, fallback, out _);

    /// <summary>
    /// As <see cref="ResolveMinimumLength(ILogger, Func{int?}, int)"/>, and additionally
    /// reports whether the value actually came from the directory.
    /// </summary>
    /// <param name="fromDirectory"><see langword="true"/> when the lookup returned a
    /// value; <see langword="false"/> when the logged fallback was used. Callers that
    /// cache the result use this to cache only real answers, so that a failing lookup
    /// keeps re-attempting and keeps logging instead of having its warning suppressed
    /// for the lifetime of a cache entry.</param>
    public static int ResolveMinimumLength(
        ILogger logger,
        Func<int?> lookup,
        int fallback,
        out bool fromDirectory)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(lookup);

        try
        {
            if (lookup() is { } minLength)
            {
                fromDirectory = true;
                return minLength;
            }

            LogLookupFailed(logger, fallback, null);
            fromDirectory = false;
            return fallback;
        }
        catch (Exception ex)
        {
            LogLookupFailed(logger, fallback, ex);
            fromDirectory = false;
            return fallback;
        }
    }
}
