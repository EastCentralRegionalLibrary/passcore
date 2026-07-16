using System;
using System.Linq;
using Microsoft.Extensions.Logging;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Tests;

public class AdministrativeResetTests
{
    private static readonly Exception BlockedFailure = DirectoryErrorTranslator.CreateChangeNotPermittedError();

    [Fact]
    public void ShouldAttempt_ChangeNotPermittedEnabledVerified_ReturnsTrue()
    {
        Assert.True(AdministrativeReset.ShouldAttempt(
            allowAdministrativeReset: true,
            currentCredentialsVerified: true,
            DirectoryFailureClass.ChangeNotPermitted));
    }

    [Fact]
    public void ShouldAttempt_NewPasswordPolicy_IsNeverRescued_PolicyIsHonored()
    {
        // Length/complexity/history/minimum-age rejections are intentional
        // domain policy; the fallback must not bypass them.
        Assert.False(AdministrativeReset.ShouldAttempt(
            allowAdministrativeReset: true,
            currentCredentialsVerified: true,
            DirectoryFailureClass.NewPasswordPolicy));
    }

    [Fact]
    public void ShouldAttempt_AccountStateInInformativeMode_IsNeverRescuedDespiteSameExceptionShape()
    {
        // In informative mode an account-state failure (e.g. locked-out 0x775)
        // is rendered as the SAME exception type and ApiErrorCode as the
        // cannot-change condition (0x8C3) — only the class differs. Prove the
        // shapes collide, then prove the class-based gate still tells them apart.
        var lockedOutInformative = DirectoryErrorTranslator.Translate(0x775, ErrorDisclosureMode.Informative);
        var cannotChange = DirectoryErrorTranslator.Translate(0x8C3, ErrorDisclosureMode.Informative);

        Assert.IsType<PasswordPolicyViolationException>(lockedOutInformative);
        Assert.IsType<PasswordPolicyViolationException>(cannotChange);
        Assert.Equal(
            ((PasswordPolicyViolationException)cannotChange).ErrorCode,
            ((PasswordPolicyViolationException)lockedOutInformative).ErrorCode);

        Assert.Equal(DirectoryFailureClass.AccountState, DirectoryErrorTranslator.Classify(0x775));
        Assert.False(AdministrativeReset.ShouldAttempt(
            allowAdministrativeReset: true,
            currentCredentialsVerified: true,
            DirectoryErrorTranslator.Classify(0x775)));

        Assert.Equal(DirectoryFailureClass.ChangeNotPermitted, DirectoryErrorTranslator.Classify(0x8C3));
        Assert.True(AdministrativeReset.ShouldAttempt(
            allowAdministrativeReset: true,
            currentCredentialsVerified: true,
            DirectoryErrorTranslator.Classify(0x8C3)));
    }

    [Theory]
    [InlineData(DirectoryFailureClass.AccountState)]     // hardened rendering — same class either mode
    [InlineData(DirectoryFailureClass.Infrastructure)]   // explicit, not incidental: never rescue or probe
    [InlineData(DirectoryFailureClass.Credentials)]
    [InlineData(DirectoryFailureClass.Existence)]
    [InlineData(DirectoryFailureClass.NewPasswordPolicy)]
    [InlineData(DirectoryFailureClass.PasswordExpiredOrMustChange)]
    public void ShouldAttempt_NonRescuableClasses_ReturnsFalse(DirectoryFailureClass failureClass)
    {
        Assert.False(AdministrativeReset.ShouldAttempt(
            allowAdministrativeReset: true,
            currentCredentialsVerified: true,
            failureClass));
    }

    [Fact]
    public void ShouldAttempt_WithoutVerifiedCredentials_IsNeverTrue()
    {
        // The account-takeover invariant: no combination of option state and
        // failure class — including ChangeNotPermitted itself and both
        // renderings of AccountState — may permit a reset without verified
        // current credentials.
        foreach (var enabled in new[] { true, false })
        {
            foreach (var failureClass in AllFailureClasses())
            {
                Assert.False(AdministrativeReset.ShouldAttempt(
                    enabled,
                    currentCredentialsVerified: false,
                    failureClass));
            }
        }
    }

    [Fact]
    public void ShouldAttempt_Disabled_IsNeverTrue()
    {
        foreach (var verified in new[] { true, false })
        {
            foreach (var failureClass in AllFailureClasses())
            {
                Assert.False(AdministrativeReset.ShouldAttempt(
                    allowAdministrativeReset: false,
                    verified,
                    failureClass));
            }
        }
    }

    [Fact]
    public void LogPerformed_EmitsWarningWithCorrelationIdUsernameAndOriginalFailure()
    {
        var logger = new CapturingLogger();

        AdministrativeReset.LogPerformed(logger, "abc12345", "jdoe", BlockedFailure);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("abc12345", entry.Message, StringComparison.Ordinal);
        Assert.Contains("jdoe", entry.Message, StringComparison.Ordinal);
        Assert.Contains(BlockedFailure.Message, entry.Message, StringComparison.Ordinal);
        Assert.Contains("ADMINISTRATIVE PASSWORD RESET", entry.Message, StringComparison.Ordinal);
        Assert.Same(BlockedFailure, entry.Exception);
    }

    [Fact]
    public void LogPerformed_NullCorrelationId_StillLogs()
    {
        var logger = new CapturingLogger();

        AdministrativeReset.LogPerformed(logger, null, "jdoe", BlockedFailure);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("n/a", entry.Message, StringComparison.Ordinal);
    }

    private static DirectoryFailureClass[] AllFailureClasses() =>
        Enum.GetValues<DirectoryFailureClass>().ToArray();

    private sealed class CapturingLogger : ILogger
    {
        public System.Collections.Generic.List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = new();

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
