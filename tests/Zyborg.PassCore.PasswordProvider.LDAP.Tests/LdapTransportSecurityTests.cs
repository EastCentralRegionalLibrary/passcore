using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Models;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

public class LdapTransportSecurityTests
{
    private static LdapPasswordChangeOptions ValidOptions() => new()
    {
        LdapHostnames = new[] { "ldap.example.com" },
        LdapPort = 636,
        LdapUsername = "cn=admin,dc=example,dc=com",
        LdapPassword = "secret",
        LdapSearchBase = "dc=example,dc=com",
        LdapSearchFilter = "(sAMAccountName={Username})",
    };

    private static LdapPasswordChangeProvider Construct(
        LdapPasswordChangeOptions opts,
        ILogger<LdapPasswordChangeProvider>? logger = null) =>
        new(
            logger ?? NullLogger<LdapPasswordChangeProvider>.Instance,
            Options.Create(opts),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>());

    [Fact]
    public void Construct_SslAndStartTlsBothEnabled_Throws()
    {
        var opts = ValidOptions();
        opts.LdapSecureSocketLayer = true;
        opts.LdapStartTls = true;

        Assert.Throws<ArgumentException>(() => Construct(opts));
    }

    [Fact]
    public void Construct_NoTransportSecurity_LogsWarning()
    {
        var logger = new CapturingLogger();

        Construct(ValidOptions(), logger);

        Assert.Contains(logger.Entries, e =>
            e.Level == LogLevel.Warning &&
            e.Message.Contains("unencrypted", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void Construct_WithTransportSecurity_DoesNotLogWarning(bool ssl, bool startTls)
    {
        var logger = new CapturingLogger();
        var opts = ValidOptions();
        opts.LdapSecureSocketLayer = ssl;
        opts.LdapStartTls = startTls;

        Construct(opts, logger);

        Assert.DoesNotContain(logger.Entries, e => e.Level == LogLevel.Warning);
    }

    [Theory]
    [InlineData(SslPolicyErrors.None)]
    [InlineData(SslPolicyErrors.RemoteCertificateChainErrors)]
    [InlineData(SslPolicyErrors.RemoteCertificateNameMismatch)]
    public void ValidateServerCertificate_IgnoreTlsErrors_AcceptsEverything(SslPolicyErrors errors)
    {
        var opts = ValidOptions();
        opts.LdapIgnoreTlsErrors = true;

        Assert.True(Validate(Construct(opts), errors));
    }

    [Fact]
    public void ValidateServerCertificate_IgnoreTlsValidation_AcceptsChainErrorsOnly()
    {
        var opts = ValidOptions();
        opts.LdapIgnoreTlsValidation = true;
        var provider = Construct(opts);

        Assert.True(Validate(provider, SslPolicyErrors.None));
        Assert.True(Validate(provider, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.False(Validate(provider, SslPolicyErrors.RemoteCertificateNameMismatch));
        Assert.False(Validate(provider,
            SslPolicyErrors.RemoteCertificateChainErrors | SslPolicyErrors.RemoteCertificateNameMismatch));
    }

    [Fact]
    public void ValidateServerCertificate_NoIgnoreFlags_AcceptsOnlyCleanResult()
    {
        var provider = Construct(ValidOptions());

        Assert.True(Validate(provider, SslPolicyErrors.None));
        Assert.False(Validate(provider, SslPolicyErrors.RemoteCertificateChainErrors));
        Assert.False(Validate(provider, SslPolicyErrors.RemoteCertificateNameMismatch));
    }

    private static bool Validate(LdapPasswordChangeProvider provider, SslPolicyErrors errors)
    {
#pragma warning disable SYSLIB0026 // Parameterless constructor is obsolete, but required here to create a dummy non-null certificate without throwing on invalid data or loading real files
        using var cert = new X509Certificate();
#pragma warning restore SYSLIB0026
        using var chain = new X509Chain();
        return provider.ValidateServerCertificate(provider, cert, chain, errors);
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
