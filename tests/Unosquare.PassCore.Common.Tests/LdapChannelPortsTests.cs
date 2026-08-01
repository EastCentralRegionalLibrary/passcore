using Unosquare.PassCore.Common;
using Xunit;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// The channel/port pairing, tested for real rather than audited from source.
///
/// <para>This logic lives in <c>Common</c> precisely so it can be: the AD provider
/// that consumes it targets <c>net8.0-windows</c> and cannot be loaded from this
/// suite at all, so anything left inside it can only ever be checked by reading
/// its text. The rule being enforced here is small, total, and was wrong in
/// production for long enough to cost several rounds of investigation — it earns a
/// real test.</para>
/// </summary>
public class LdapChannelPortsTests
{
    /// <summary>
    /// The defect this type exists to prevent. A sealed bind is plain LDAP, and
    /// 636 is TLS from the first byte: the BindRequest is not a protocol the
    /// server can answer, and the client reports <c>0x8007203A</c> "the server is
    /// not operational" — which reads as a directory fault and is not one.
    /// </summary>
    [Fact]
    public void ASealedBindIsNeverAttemptedAgainstTheLdapsPort()
    {
        Assert.Null(LdapChannelPorts.SealedPortFor(LdapChannelPorts.Secure));
    }

    /// <summary>
    /// The mirror image: an SSL bind must not target the plaintext port, which is
    /// not listening for a TLS ClientHello. The substitution is what guarantees
    /// this for the default configuration, where the fallback would otherwise
    /// inherit 389.
    /// </summary>
    [Fact]
    public void AnSslBindIsNeverAttemptedAgainstThePlaintextPort()
    {
        Assert.NotEqual(LdapChannelPorts.Plaintext, LdapChannelPorts.SslPortFor(LdapChannelPorts.Plaintext));
        Assert.Equal(LdapChannelPorts.Secure, LdapChannelPorts.SslPortFor(LdapChannelPorts.Plaintext));
    }

    /// <summary>
    /// The default configuration is unaffected: 389 still gets a sealed bind on
    /// 389, which is the path every current deployment and every passing CI
    /// assertion runs on.
    /// </summary>
    [Fact]
    public void ThePlaintextDefaultStillSealsOnThePlaintextPort()
    {
        Assert.Equal(LdapChannelPorts.Plaintext, LdapChannelPorts.SealedPortFor(LdapChannelPorts.Plaintext));
    }

    /// <summary>
    /// A non-standard port is a real deployment shape, and is honoured rather than
    /// second-guessed. Only the two well-known ports carry protocol meaning that
    /// can be inferred; anything else is the operator's decision and both
    /// mechanisms target it as configured.
    /// </summary>
    [Theory]
    [InlineData(3268)]
    [InlineData(1389)]
    [InlineData(10389)]
    public void ANonStandardPortIsHonouredByBothMechanisms(int port)
    {
        Assert.Equal(port, LdapChannelPorts.SealedPortFor(port));
        Assert.Equal(port, LdapChannelPorts.SslPortFor(port));
    }

    /// <summary>
    /// Whatever the configured port, the pair produced can never be one of the two
    /// combinations that cannot work. Stated as a property over the ports a
    /// deployment might plausibly carry, so a future edit to either rule has to
    /// break this rather than merely disagree with a table.
    /// </summary>
    [Fact]
    public void NoConfiguredPortCanProduceAnUnworkableCombination()
    {
        foreach (var configured in new[] { 389, 636, 3268, 3269, 1389, 10636, 1, 65535 })
        {
            var sealedPort = LdapChannelPorts.SealedPortFor(configured);
            var sslPort = LdapChannelPorts.SslPortFor(configured);

            Assert.True(
                sealedPort != LdapChannelPorts.Secure,
                $"Configured port {configured} produced a sealed bind against the LDAPS port.");

            Assert.True(
                sslPort != LdapChannelPorts.Plaintext,
                $"Configured port {configured} produced an SSL bind against the plaintext port.");
        }
    }
}
