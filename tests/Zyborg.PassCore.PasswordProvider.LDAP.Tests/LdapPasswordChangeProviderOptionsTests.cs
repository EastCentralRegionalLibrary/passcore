using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Models;
using Zyborg.PassCore.PasswordProvider.LDAP;
using Xunit;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

public class LdapPasswordChangeProviderOptionsTests
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

    private static LdapPasswordChangeProvider Construct(LdapPasswordChangeOptions opts) =>
        new(
            NullLogger<LdapPasswordChangeProvider>.Instance,
            Options.Create(opts),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>());

    [Fact]
    public void Construct_WithValidOptions_Succeeds()
    {
        var provider = Construct(ValidOptions());
        Assert.NotNull(provider);
    }

    [Fact]
    public void Construct_NullOptionsContainer_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new LdapPasswordChangeProvider(
            NullLogger<LdapPasswordChangeProvider>.Instance,
            options: null!,
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>()));
    }

    [Fact]
    public void Construct_NoHostnames_Throws()
    {
        var opts = ValidOptions();
        opts.LdapHostnames = Array.Empty<string>();

        Assert.Throws<ArgumentException>(() => Construct(opts));
    }

    [Fact]
    public void Construct_NoBindDn_Throws()
    {
        var opts = ValidOptions();
        opts.LdapUsername = string.Empty;

        Assert.Throws<ArgumentException>(() => Construct(opts));
    }

    [Fact]
    public void Construct_NoBindPassword_Throws()
    {
        var opts = ValidOptions();
        opts.LdapPassword = string.Empty;

        Assert.Throws<ArgumentException>(() => Construct(opts));
    }

    [Fact]
    public void Construct_NoSearchBase_Throws()
    {
        var opts = ValidOptions();
        opts.LdapSearchBase = string.Empty;

        Assert.Throws<ArgumentException>(() => Construct(opts));
    }

    [Fact]
    public void Construct_SearchFilterMissingUsernamePlaceholder_Throws()
    {
        var opts = ValidOptions();
        opts.LdapSearchFilter = "(sAMAccountName=someone)";

        Assert.Throws<ArgumentException>(() => Construct(opts));
    }
}
