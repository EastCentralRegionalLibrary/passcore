using System;
using Microsoft.Extensions.Logging;

namespace Unosquare.PassCore.Common;

/// <summary>
/// A short-lived cache over the domain's minimum password length.
/// </summary>
/// <remarks>
/// <para>The lookup behind this runs on <b>every</b> POST to the password endpoint,
/// before the caller has proved anything, and costs a bind plus two searches. The
/// value it fetches is domain-wide and changes about as often as a group policy
/// edit, so re-reading it per request buys nothing and hands an unauthenticated
/// caller a cheap way to generate directory load.</para>
/// <para>Only a value that actually came from the directory is cached. The logged
/// fallback is not: caching it would suppress the operator-actionable warning for
/// the whole TTL, which is precisely the signal that something is wrong. A failing
/// lookup therefore keeps re-attempting and keeps logging, exactly as before.</para>
/// <para>Nothing account-specific belongs here. This caches one domain-wide policy
/// number and nothing else — no membership, no credentials, no distinguished
/// names.</para>
/// </remarks>
public sealed class CachedDomainMinimumLength
{
    /// <summary>
    /// How long a directory-sourced value is reused. Long enough to collapse a burst
    /// of requests onto one lookup, short enough that a policy change is picked up
    /// without a restart. A stale value for a few minutes only affects the advertised
    /// client-side minimum; the directory still enforces the real one on submit.
    /// </summary>
    public static readonly TimeSpan DefaultTimeToLive = TimeSpan.FromMinutes(5);

    private readonly TimeSpan _timeToLive;
    private readonly Func<DateTimeOffset> _clock;
    private readonly object _gate = new();

    private int? _cachedValue;
    private DateTimeOffset _expiresAt;

    /// <summary>Creates a cache with the default time-to-live and the system clock.</summary>
    public CachedDomainMinimumLength()
        : this(DefaultTimeToLive)
    {
    }

    /// <summary>Creates a cache with an explicit time-to-live, and optionally an injected clock for tests.</summary>
    /// <param name="timeToLive">How long a directory-sourced value is reused.</param>
    /// <param name="clock">Supplies the current time; defaults to <see cref="DateTimeOffset.UtcNow"/>.</param>
    public CachedDomainMinimumLength(TimeSpan timeToLive, Func<DateTimeOffset>? clock = null)
    {
        if (timeToLive < TimeSpan.Zero)
            throw new ArgumentOutOfRangeException(nameof(timeToLive), timeToLive, "Time-to-live cannot be negative.");

        _timeToLive = timeToLive;
        _clock = clock ?? (() => DateTimeOffset.UtcNow);
    }

    /// <summary>
    /// Returns the cached minimum length when one is still fresh, otherwise performs
    /// the lookup through <see cref="DomainPasswordPolicy.ResolveMinimumLength(ILogger, Func{int?}, int, out bool)"/>
    /// and caches it if it came from the directory.
    /// </summary>
    /// <param name="logger">The provider's logger.</param>
    /// <param name="lookup">The directory-specific lookup.</param>
    /// <param name="fallback">The value to advertise when the lookup yields nothing.</param>
    /// <returns>The resolved minimum length.</returns>
    public int Resolve(
        ILogger logger,
        Func<int?> lookup,
        int fallback = DomainPasswordPolicy.DefaultMinimumLength)
    {
        lock (_gate)
        {
            if (_cachedValue is { } cached && _clock() < _expiresAt)
                return cached;
        }

        // Deliberately outside the lock: the lookup is a network round trip, and
        // holding a lock across it would serialize every concurrent request behind
        // the slowest one. A few racing requests may each perform a lookup; they
        // resolve to the same domain-wide value, so the only cost is a duplicated
        // read that the next request will not repeat.
        var resolved = DomainPasswordPolicy.ResolveMinimumLength(logger, lookup, fallback, out var fromDirectory);

        if (!fromDirectory)
            return resolved;

        lock (_gate)
        {
            _cachedValue = resolved;
            _expiresAt = _clock().Add(_timeToLive);
        }

        return resolved;
    }
}
