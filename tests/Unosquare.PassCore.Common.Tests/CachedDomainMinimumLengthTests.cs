using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// The minimum-length lookup runs on every POST to the password endpoint, before
/// the caller has proved anything, and costs a bind plus two searches. The value
/// is domain-wide, so re-reading it per request buys nothing and hands an
/// unauthenticated caller a cheap way to generate directory load.
/// </summary>
public class CachedDomainMinimumLengthTests
{
    [Fact]
    public void WithinTheTimeToLive_TheValueIsNotFetchedAgain()
    {
        var now = DateTimeOffset.UnixEpoch;
        var cache = new CachedDomainMinimumLength(TimeSpan.FromMinutes(5), () => now);
        var lookups = 0;

        int? Lookup()
        {
            lookups++;
            return 14;
        }

        Assert.Equal(14, cache.Resolve(NullLogger.Instance, Lookup));

        now = now.AddMinutes(4);
        Assert.Equal(14, cache.Resolve(NullLogger.Instance, Lookup));
        Assert.Equal(14, cache.Resolve(NullLogger.Instance, Lookup));

        Assert.Equal(1, lookups);
    }

    [Fact]
    public void OnceTheTimeToLiveExpires_TheValueIsFetchedAgain()
    {
        var now = DateTimeOffset.UnixEpoch;
        var cache = new CachedDomainMinimumLength(TimeSpan.FromMinutes(5), () => now);
        var lookups = 0;

        int? Lookup()
        {
            lookups++;
            return 8 + lookups;
        }

        Assert.Equal(9, cache.Resolve(NullLogger.Instance, Lookup));

        now = now.AddMinutes(5).AddSeconds(1);
        Assert.Equal(10, cache.Resolve(NullLogger.Instance, Lookup));
        Assert.Equal(2, lookups);
    }

    /// <summary>
    /// The fallback must never be cached. Caching it would suppress the
    /// operator-actionable warning for the whole TTL — and that warning is the only
    /// signal that PassCore is advertising a weaker minimum than the domain
    /// enforces.
    /// </summary>
    [Fact]
    public void AFailedLookup_StillLogsAndFallsBack_EveryTime()
    {
        var now = DateTimeOffset.UnixEpoch;
        var cache = new CachedDomainMinimumLength(TimeSpan.FromMinutes(5), () => now);
        var logger = new CapturingLogger();
        var lookups = 0;

        int? Failing()
        {
            lookups++;
            throw new InvalidOperationException("directory unreachable");
        }

        Assert.Equal(DomainPasswordPolicy.DefaultMinimumLength, cache.Resolve(logger, Failing));
        Assert.Equal(DomainPasswordPolicy.DefaultMinimumLength, cache.Resolve(logger, Failing));

        Assert.Equal(2, lookups);
        Assert.Equal(2, logger.Entries.Count);
        Assert.All(logger.Entries, e => Assert.Equal(LogLevel.Warning, e.Level));
    }

    /// <summary>A lookup that returns nothing is the same case: logged fallback, not cached.</summary>
    [Fact]
    public void AnAbsentValue_IsAlsoNotCached()
    {
        var cache = new CachedDomainMinimumLength(TimeSpan.FromMinutes(5), () => DateTimeOffset.UnixEpoch);
        var logger = new CapturingLogger();
        var lookups = 0;

        int? Absent()
        {
            lookups++;
            return null;
        }

        cache.Resolve(logger, Absent);
        cache.Resolve(logger, Absent);

        Assert.Equal(2, lookups);
        Assert.Equal(2, logger.Entries.Count);
    }

    /// <summary>A failure after a success keeps serving the cached value; it does not poison it.</summary>
    [Fact]
    public void AFailureAfterASuccess_DoesNotDiscardTheCachedValue()
    {
        var now = DateTimeOffset.UnixEpoch;
        var cache = new CachedDomainMinimumLength(TimeSpan.FromMinutes(5), () => now);

        Assert.Equal(12, cache.Resolve(NullLogger.Instance, () => 12));
        Assert.Equal(12, cache.Resolve(NullLogger.Instance, () => throw new InvalidOperationException("down")));
    }

    private sealed class NullLogger : ILogger
    {
        public static readonly NullLogger Instance = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
        {
        }
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception), exception));
    }
}
