namespace Unosquare.PassCore.Common;

/// <summary>
/// Pairs a channel-protection mechanism with the port that can actually serve it.
/// </summary>
/// <remarks>
/// <para>Port and channel are <b>not</b> independent settings, and treating them as
/// such produces connections that cannot work regardless of the directory:</para>
/// <list type="bullet">
///   <item><description>Port 389 speaks plain LDAP and upgrades <em>in band</em> —
///   SASL sign-and-seal, or StartTLS. It is not listening for a TLS
///   ClientHello.</description></item>
///   <item><description>Port 636 is TLS from the first byte, unconditionally. An
///   LDAP BindRequest arriving on it is not a protocol the server can answer, and
///   the client reports it as <c>0x8007203A</c>, "the server is not
///   operational".</description></item>
/// </list>
/// <para>That error was read as a directory problem for several rounds of
/// investigation before being recognised as self-inflicted: a sealed bind was
/// being attempted against whatever port was configured, including 636. Encoding
/// the pairing here makes the invalid combination unrepresentable rather than
/// merely discouraged.</para>
/// <para>Note that StartTLS — plain LDAP on 389 upgraded in band — is a third
/// mechanism that <c>ContextOptions</c> cannot express at all, which is why it
/// does not appear here.</para>
/// </remarks>
public static class LdapChannelPorts
{
    /// <summary>The standard plaintext LDAP port, and the default for <c>LdapPort</c>.</summary>
    public const int Plaintext = 389;

    /// <summary>The standard LDAPS port.</summary>
    public const int Secure = 636;

    /// <summary>
    /// The port a sign-and-seal (non-SSL) bind should target, or <see langword="null"/>
    /// when such a bind cannot be attempted at all.
    /// </summary>
    /// <remarks>
    /// Returns <see langword="null"/> for the LDAPS port. An operator who configured
    /// 636 has asked for LDAPS, so the honest response is to skip the sealed attempt
    /// rather than either making it in a form that cannot succeed, or silently
    /// connecting to a different port than the one configured.
    /// </remarks>
    public static int? SealedPortFor(int configuredPort) =>
        configuredPort == Secure ? null : configuredPort;

    /// <summary>
    /// The port an SSL bind should target.
    /// </summary>
    /// <remarks>
    /// The plaintext default means the operator did not choose a port, so the
    /// well-known LDAPS port is substituted. Any other value is taken as deliberate
    /// and left alone — a directory on a non-standard port is a real deployment
    /// shape, and second-guessing it would be worse than honouring it.
    /// </remarks>
    public static int SslPortFor(int configuredPort) =>
        configuredPort == Plaintext ? Secure : configuredPort;
}
