using System;
using System.Collections.Generic;
using System.ComponentModel;
using Microsoft.Extensions.Logging;

namespace Unosquare.PassCore.Common.Tests;

public class ServiceAccountFailureTests
{
    [Fact]
    public void Log_EmitsWarningWithCorrelationIdOperationHostAndUnderlyingCode()
    {
        var logger = new CapturingLogger();
        var failure = new Win32Exception(0x52E); // ERROR_LOGON_FAILURE

        ServiceAccountFailure.Log(logger, "abc12345", "service-account bind", "dc1.example.com", failure);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("abc12345", entry.Message, StringComparison.Ordinal);
        Assert.Contains("service-account bind", entry.Message, StringComparison.Ordinal);
        Assert.Contains("dc1.example.com", entry.Message, StringComparison.Ordinal);
        Assert.Contains("0x52E", entry.Message, StringComparison.Ordinal);
        Assert.Same(failure, entry.Exception);
    }

    [Fact]
    public void Log_NullCorrelationIdAndUnrecoverableCode_StillLogsWithPlaceholders()
    {
        var logger = new CapturingLogger();
        var failure = new InvalidOperationException("no win32 code here");

        ServiceAccountFailure.Log(logger, correlationId: null, "service-account connect", host: null, failure);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("n/a", entry.Message, StringComparison.Ordinal);
        Assert.Contains("unknown", entry.Message, StringComparison.Ordinal);
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
