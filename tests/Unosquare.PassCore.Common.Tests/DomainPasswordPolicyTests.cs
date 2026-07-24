using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Unosquare.PassCore.Common.Tests;

public class DomainPasswordPolicyTests
{
    [Fact]
    public void ResolveMinimumLength_LookupReturnsValue_ReturnsItWithoutLogging()
    {
        var logger = new CapturingLogger();

        var result = DomainPasswordPolicy.ResolveMinimumLength(logger, () => 14);

        Assert.Equal(14, result);
        Assert.Empty(logger.Entries);
    }

    [Fact]
    public void ResolveMinimumLength_LookupReturnsNull_LogsWarningAndReturnsFallback()
    {
        var logger = new CapturingLogger();

        var result = DomainPasswordPolicy.ResolveMinimumLength(logger, () => null);

        Assert.Equal(DomainPasswordPolicy.DefaultMinimumLength, result);
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("minPwdLength", entry.Message, StringComparison.Ordinal);
        Assert.Null(entry.Exception);
    }

    [Fact]
    public void ResolveMinimumLength_LookupThrows_LogsWarningWithExceptionAndReturnsFallback()
    {
        var logger = new CapturingLogger();
        var boom = new InvalidOperationException("DC unreachable");

        var result = DomainPasswordPolicy.ResolveMinimumLength(logger, () => throw boom);

        Assert.Equal(DomainPasswordPolicy.DefaultMinimumLength, result);
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Same(boom, entry.Exception);
    }

    [Fact]
    public void ResolveMinimumLength_CustomFallback_IsHonored()
    {
        var logger = new CapturingLogger();

        var result = DomainPasswordPolicy.ResolveMinimumLength(logger, () => null, fallback: 12);

        Assert.Equal(12, result);
    }

    [Fact]
    public void ResolveMinimumLength_NeverThrows_EvenWhenLookupDoes()
    {
        var logger = new CapturingLogger();

        var ex = Record.Exception(() =>
            DomainPasswordPolicy.ResolveMinimumLength(logger, () => throw new TimeoutException()));

        Assert.Null(ex);
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception), exception));
    }
}
