using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Models;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

public class LdapDisclosureOptionsTests
{
    private static LdapPasswordChangeOptions ValidOptions() => new()
    {
        LdapHostnames = new[] { "ldap.example.com" },
        LdapPort = 636,
        LdapUsername = "cn=admin,dc=example,dc=com",
        LdapPassword = "secret",
        LdapSearchBase = "dc=example,dc=com",
        LdapSearchFilter = "(sAMAccountName={Username})",
        LdapSecureSocketLayer = true,
    };

    private static CapturingLogger Construct(LdapPasswordChangeOptions opts)
    {
        var logger = new CapturingLogger();
        _ = new LdapPasswordChangeProvider(
            logger,
            Options.Create(opts),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>());
        return logger;
    }

    [Fact]
    public void Construct_DefaultDisclosureMode_IsHardened()
    {
        Assert.Equal(ErrorDisclosureMode.Hardened, new LdapPasswordChangeOptions().ErrorDisclosureMode);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void Construct_DeprecatedHideUserNotFoundConfigured_LogsWarning(bool value)
    {
        var opts = ValidOptions();
        opts.HideUserNotFound = value;

        var logger = Construct(opts);

        Assert.Contains(logger.Entries, e =>
            e.Level == LogLevel.Warning &&
            e.Message.Contains("HideUserNotFound", StringComparison.Ordinal) &&
            e.Message.Contains("ErrorDisclosureMode", StringComparison.Ordinal));
    }

    [Fact]
    public void Construct_HideUserNotFoundAbsent_DoesNotLogDeprecationWarning()
    {
        var logger = Construct(ValidOptions());

        Assert.DoesNotContain(logger.Entries, e =>
            e.Message.Contains("HideUserNotFound", StringComparison.Ordinal));
    }

    [Fact]
    public void Construct_AdminResetWithReplaceMechanism_LogsIneffectiveWarning()
    {
        var opts = ValidOptions();
        opts.AllowAdministrativeReset = true;
        opts.LdapChangePasswordWithDelAdd = false;

        var logger = Construct(opts);

        Assert.Contains(logger.Entries, e =>
            e.Level == LogLevel.Warning &&
            e.Message.Contains("AllowAdministrativeReset", StringComparison.Ordinal) &&
            e.Message.Contains("no effect", StringComparison.Ordinal));
    }

    [Fact]
    public void Construct_AdminResetWithDelAddMechanism_DoesNotLogIneffectiveWarning()
    {
        var opts = ValidOptions();
        opts.AllowAdministrativeReset = true;
        opts.LdapChangePasswordWithDelAdd = true;

        var logger = Construct(opts);

        Assert.DoesNotContain(logger.Entries, e =>
            e.Message.Contains("AllowAdministrativeReset", StringComparison.Ordinal));
    }

    private sealed class CapturingLogger : ILogger<LdapPasswordChangeProvider>
    {
        public List<(LogLevel Level, string Message)> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception)));
    }
}
