using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Tests;

public class AdministrativeResetTests
{
    private static readonly Exception PolicyFailure =
        new PasswordPolicyViolationException("policy", ApiErrorCode.ComplexPassword);

    private static readonly Exception CannotChangeFailure =
        new PasswordPolicyViolationException("cannot change", ApiErrorCode.ChangeNotPermitted);

    private static readonly Exception CredentialsFailure =
        new InvalidCredentialsException("bad password");

    private static readonly Exception InfraFailure =
        new DirectoryUnavailableException("directory down");

    [Fact]
    public void ShouldAttempt_EnabledVerifiedPolicyFailure_ReturnsTrue()
    {
        Assert.True(AdministrativeReset.ShouldAttempt(
            allowAdministrativeReset: true,
            currentCredentialsVerified: true,
            PolicyFailure));

        Assert.True(AdministrativeReset.ShouldAttempt(
            allowAdministrativeReset: true,
            currentCredentialsVerified: true,
            CannotChangeFailure));
    }

    [Fact]
    public void ShouldAttempt_WithoutVerifiedCredentials_IsNeverTrue()
    {
        // The account-takeover invariant: no combination of option state and
        // failure type may permit a reset without verified current credentials.
        foreach (var enabled in new[] { true, false })
        {
            foreach (var failure in AllFailureShapes())
            {
                Assert.False(AdministrativeReset.ShouldAttempt(
                    enabled,
                    currentCredentialsVerified: false,
                    failure));
            }
        }
    }

    [Fact]
    public void ShouldAttempt_Disabled_IsNeverTrue()
    {
        foreach (var verified in new[] { true, false })
        {
            foreach (var failure in AllFailureShapes())
            {
                Assert.False(AdministrativeReset.ShouldAttempt(
                    allowAdministrativeReset: false,
                    verified,
                    failure));
            }
        }
    }

    [Fact]
    public void ShouldAttempt_NonRescuableFailures_ReturnsFalse()
    {
        // Wrong credentials, infrastructure trouble, unknown users and raw
        // exceptions are never cured by an administrative reset.
        foreach (var failure in new[]
        {
            CredentialsFailure,
            InfraFailure,
            new UserNotFoundException("nope"),
            new Exception("raw"),
            (Exception?)null,
        })
        {
            Assert.False(AdministrativeReset.ShouldAttempt(
                allowAdministrativeReset: true,
                currentCredentialsVerified: true,
                failure));
        }
    }

    [Fact]
    public void LogPerformed_EmitsWarningWithCorrelationIdUsernameAndOriginalFailure()
    {
        var logger = new CapturingLogger();

        AdministrativeReset.LogPerformed(logger, "abc12345", "jdoe", PolicyFailure);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("abc12345", entry.Message, StringComparison.Ordinal);
        Assert.Contains("jdoe", entry.Message, StringComparison.Ordinal);
        Assert.Contains(PolicyFailure.Message, entry.Message, StringComparison.Ordinal);
        Assert.Contains("ADMINISTRATIVE PASSWORD RESET", entry.Message, StringComparison.Ordinal);
        Assert.Same(PolicyFailure, entry.Exception);
    }

    [Fact]
    public void LogPerformed_NullCorrelationId_StillLogs()
    {
        var logger = new CapturingLogger();

        AdministrativeReset.LogPerformed(logger, null, "jdoe", PolicyFailure);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("n/a", entry.Message, StringComparison.Ordinal);
    }

    private static IEnumerable<Exception> AllFailureShapes() =>
        new[] { PolicyFailure, CannotChangeFailure, CredentialsFailure, InfraFailure, new Exception("raw") };

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
