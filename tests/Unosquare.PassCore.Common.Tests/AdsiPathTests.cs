using System;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// The AD provider passed a bare "host:port" to DirectoryEntry, which is not an
/// ADSI path. Every request on the explicit-bind path failed with 0x80005000
/// (E_ADS_BAD_PATHNAME) and advertised the fallback minimum length of 6.
/// </summary>
public class AdsiPathTests
{
    [Fact]
    public void RootDsePath_HasASchemeAndTheRootDseEntryPoint()
    {
        var path = AdsiPath.ForRootDse("dc.example.com", 389);

        Assert.Equal("LDAP://dc.example.com:389/RootDSE", path);
        Assert.StartsWith(AdsiPath.LdapScheme, path, StringComparison.Ordinal);
    }

    /// <summary>
    /// The naming context is the whole point: minPwdLength lives on the domain
    /// object, so a path that stops at the server binds something that does not
    /// carry the attribute and yields null rather than an error.
    /// </summary>
    [Fact]
    public void NamingContextPath_HasASchemeAndTheNamingContext()
    {
        var path = AdsiPath.ForNamingContext("dc.example.com", 389, "DC=example,DC=com");

        Assert.Equal("LDAP://dc.example.com:389/DC=example,DC=com", path);
        Assert.StartsWith(AdsiPath.LdapScheme, path, StringComparison.Ordinal);
        Assert.EndsWith("DC=example,DC=com", path, StringComparison.Ordinal);
    }

    /// <summary>
    /// The regression in one assertion: whatever else changes, the path must
    /// carry a provider scheme and must not be a bare host:port.
    /// </summary>
    [Theory]
    [InlineData(389)]
    [InlineData(636)]
    public void EveryPath_CarriesAProviderScheme(int port)
    {
        foreach (var path in new[]
                 {
                     AdsiPath.ForRootDse("example.com", port),
                     AdsiPath.ForNamingContext("example.com", port, "DC=example,DC=com"),
                 })
        {
            Assert.Contains("://", path, StringComparison.Ordinal);
            Assert.DoesNotMatch("^[^:]+:[0-9]+$", path);
        }
    }

    [Fact]
    public void NonDefaultPort_IsCarriedThrough()
    {
        Assert.Equal(
            "LDAP://example.com:3268/DC=example,DC=com",
            AdsiPath.ForNamingContext("example.com", 3268, "DC=example,DC=com"));
    }

    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void AnEmptyHost_IsRejected(string? host)
    {
        Assert.Throws<ArgumentException>(() => AdsiPath.ForRootDse(host!, 389));
    }

    /// <summary>
    /// An empty naming context would produce a trailing-slash path that binds the
    /// server root — the silent-null case this exists to prevent.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData(null)]
    public void AnEmptyNamingContext_IsRejected(string? namingContext)
    {
        Assert.Throws<ArgumentException>(
            () => AdsiPath.ForNamingContext("example.com", 389, namingContext!));
    }

    [Theory]
    [InlineData(0)]
    [InlineData(-1)]
    [InlineData(70000)]
    public void AnOutOfRangePort_IsRejected(int port)
    {
        Assert.Throws<ArgumentOutOfRangeException>(() => AdsiPath.ForRootDse("example.com", port));
    }
}
