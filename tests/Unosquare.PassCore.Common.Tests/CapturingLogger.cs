using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// An <see cref="ILogger"/> that records every entry verbatim, including the
/// exception passed to it, so tests can assert on level, formatted message,
/// and exception identity together. Shared by <see cref="AdministrativeResetTests"/>
/// and <see cref="PerformGatedPasswordWriteTests"/>: both need to observe
/// <see cref="AdministrativeReset.LogPerformed"/> calls, and a single
/// implementation keeps their expectations from drifting apart.
/// </summary>
internal sealed class CapturingLogger : ILogger
{
    public List<(LogLevel Level, EventId EventId, string Message, Exception? Exception)> Entries { get; } = new();

    public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

    public bool IsEnabled(LogLevel logLevel) => true;

    public void Log<TState>(
        LogLevel logLevel,
        EventId eventId,
        TState state,
        Exception? exception,
        Func<TState, Exception?, string> formatter) =>
        Entries.Add((logLevel, eventId, formatter(state, exception), exception));
}
