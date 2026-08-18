using Moq;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Models;
using Xunit;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// Only SECURITY groups may satisfy a configured group name.
///
/// <para><b>Why.</b> A distribution group cannot enter a Windows access token, so it
/// carries no authorization anywhere else in Windows, and on many directories users
/// can add themselves to one. A group a user can join must not be able to satisfy
/// <c>AllowedAdGroups</c>, and an administrator converting a group from security to
/// distribution must not be able to quietly step out of
/// <c>RestrictedAdGroups</c>.</para>
///
/// <para><b>The three outcomes, all asserted here.</b> <c>groupType</c> with the
/// security bit set matches; <c>groupType</c> with it clear does not, and warns;
/// <c>groupType</c> absent matches, because non-AD directories publish no such
/// attribute and an unconditional rule would match nothing at all there.</para>
/// </summary>
public class GroupTypeMatchingTests
{
    // Global security group: 0x80000002, which AD publishes as a signed decimal.
    private const string SecurityGroupType = "-2147483646";

    // Global group with the security bit clear: a distribution group.
    private const string DistributionGroupType = "2";

    private const string GroupDn = "cn=TargetGroup,ou=groups,dc=example,dc=com";

    private static LdapPasswordChangeOptions CreateOptions() => new()
    {
        LdapHostnames = new[] { "ldap.example.com" },
        LdapPort = 389,
        LdapUsername = "cn=admin,dc=example,dc=com",
        LdapPassword = "secret",
        LdapSearchBase = "dc=example,dc=com",
        LdapSearchFilter = "(sAMAccountName={Username})",
    };

    /// <summary>
    /// Builds a provider whose directory holds one user, a direct member of
    /// <see cref="GroupDn"/>, and that group carrying <paramref name="groupType"/> —
    /// or no <c>groupType</c> attribute at all when it is <see langword="null"/>.
    /// </summary>
    private static TestLdapPasswordChangeProvider CreateProvider(
        string? groupType, ILogger<LdapPasswordChangeProvider> logger)
    {
        var provider = new TestLdapPasswordChangeProvider(
            logger,
            Options.Create(CreateOptions()),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>());

        var userAttrs = new LdapAttributeSet
        {
            new LdapAttribute("distinguishedName", "cn=testuser,ou=people,dc=example,dc=com"),
            new LdapAttribute("sAMAccountName", "testuser"),
            new LdapAttribute("memberOf", GroupDn),
        };
        var userEntry = new LdapEntry("cn=testuser,ou=people,dc=example,dc=com", userAttrs);

        var groupAttrs = new LdapAttributeSet();
        if (groupType is not null)
            groupAttrs.Add(new LdapAttribute("groupType", groupType));
        var groupEntry = new LdapEntry(GroupDn, groupAttrs);

        provider.OnSearchLdap = (filter, attrs) =>
        {
            if (filter.Contains("sAMAccountName=", StringComparison.Ordinal))
                return Results(userEntry);

            // The group-type read: a base-scope (objectClass=*) asking for groupType.
            if (attrs.Contains("groupType"))
                return Results(groupEntry);

            return Results();
        };

        return provider;
    }

    private static ILdapSearchResults Results(params LdapEntry[] entries)
    {
        var remaining = new Queue<LdapEntry>(entries);
        var mock = new Mock<ILdapSearchResults>();
        mock.Setup(s => s.HasMoreAsync(It.IsAny<System.Threading.CancellationToken>())).ReturnsAsync(() => remaining.Count > 0);
        mock.Setup(s => s.NextAsync(It.IsAny<System.Threading.CancellationToken>())).ReturnsAsync(() => remaining.Dequeue());
        return mock.Object;
    }

    [Fact]
    public async Task ASecurityGroup_Matches()
    {
        var provider = CreateProvider(SecurityGroupType, NullLogger<LdapPasswordChangeProvider>.Instance);

        Assert.True(await provider.IsMemberOfGroupAsync("testuser", "TargetGroup"));
    }

    /// <summary>
    /// The assertion that actually constrains the change: before it, this returned
    /// true. A distribution group named in a list must not satisfy it.
    /// </summary>
    [Fact]
    public async Task ADistributionGroup_DoesNotMatch()
    {
        var provider = CreateProvider(DistributionGroupType, NullLogger<LdapPasswordChangeProvider>.Instance);

        Assert.False(await provider.IsMemberOfGroupAsync("testuser", "TargetGroup"));
    }

    /// <summary>
    /// The refusal above must not be silent. Group type is mutable, so an
    /// administrator converting a group from security to distribution would otherwise
    /// disable every restriction naming it with no signal at all — this warning is
    /// the mitigation that makes the deny-list case safe.
    ///
    /// <para>Exactly once, too. The same group is visible to both the direct
    /// <c>memberOf</c> pass and the in-chain search, so without deduplication one
    /// rejected group reads as two problems.</para>
    /// </summary>
    [Fact]
    public async Task ADistributionGroup_IsReportedRatherThanSilentlyIgnored()
    {
        var logger = new CapturingLogger();
        var provider = CreateProvider(DistributionGroupType, logger);

        await provider.IsMemberOfGroupAsync("testuser", "TargetGroup");

        var warning = Assert.Single(
            logger.Entries, e => e.EventId.Id == 113);

        Assert.Equal(LogLevel.Warning, warning.Level);

        // The operator has to be able to act on it, so both the configured name they
        // wrote and the group it resolved to have to appear.
        Assert.Contains("TargetGroup", warning.Message, StringComparison.Ordinal);
        Assert.Contains(GroupDn, warning.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The non-AD fallback. OpenLDAP's <c>groupOfNames</c> carries no <c>groupType</c>,
    /// and applying a security-only rule unconditionally would match nothing on such a
    /// directory — the provider would stop working against non-AD servers entirely.
    ///
    /// <para>This is the test that makes the fallback <em>reachable</em> rather than
    /// merely written down, which is why it is asserted separately from the smoke
    /// tests that happen to depend on it.</para>
    /// </summary>
    [Fact]
    public async Task AGroupWithNoGroupTypeAttribute_StillMatches()
    {
        var provider = CreateProvider(groupType: null, NullLogger<LdapPasswordChangeProvider>.Instance);

        Assert.True(await provider.IsMemberOfGroupAsync("testuser", "TargetGroup"));
    }

    /// <summary>
    /// ...and does so quietly. A directory that publishes no group types is behaving
    /// normally, not degraded, so it must not produce a warning per request.
    /// </summary>
    [Fact]
    public async Task AGroupWithNoGroupTypeAttribute_DoesNotWarn()
    {
        var logger = new CapturingLogger();
        var provider = CreateProvider(groupType: null, logger);

        await provider.IsMemberOfGroupAsync("testuser", "TargetGroup");

        // Scoped to the group-type events (113/114) on purpose: the constructor warns
        // separately about transport security, which these options deliberately leave
        // off and which has nothing to do with this.
        Assert.DoesNotContain(
            logger.Entries,
            e => e.EventId.Id is 113 or 114 && e.Level >= LogLevel.Warning);
    }

    /// <summary>
    /// An unparseable <c>groupType</c> is treated as absent rather than as a
    /// distribution group. Guessing "not a security group" from a value that cannot be
    /// read would turn a directory-data oddity into a silent authorization change.
    /// </summary>
    [Theory]
    [InlineData("")]
    [InlineData("   ")]
    [InlineData("not-a-number")]
    public async Task AnUnreadableGroupTypeValue_IsTreatedAsAbsent(string groupType)
    {
        var provider = CreateProvider(groupType, NullLogger<LdapPasswordChangeProvider>.Instance);

        Assert.True(await provider.IsMemberOfGroupAsync("testuser", "TargetGroup"));
    }

    /// <summary>
    /// A group whose type cannot be read at all — the entry does not come back — is
    /// also treated as eligible.
    ///
    /// <para>This is the one failure in this file that does NOT become "undetermined",
    /// and it is deliberate. The security-groups-only rule is a narrowing layered on a
    /// check that previously asked the directory nothing extra; letting an
    /// unanswerable type question refuse the request would introduce a fresh
    /// environmental dependency capable of failing every request, which is the exact
    /// fragility this change exists to remove. It is also the safe direction where it
    /// matters: still matching means a name in <c>RestrictedAdGroups</c> still
    /// refuses.</para>
    /// </summary>
    [Fact]
    public async Task AGroupWhoseEntryCannotBeRead_IsTreatedAsAbsentRatherThanRefusing()
    {
        var provider = new TestLdapPasswordChangeProvider(
            NullLogger<LdapPasswordChangeProvider>.Instance,
            Options.Create(CreateOptions()),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>());

        var userAttrs = new LdapAttributeSet
        {
            new LdapAttribute("distinguishedName", "cn=testuser,ou=people,dc=example,dc=com"),
            new LdapAttribute("sAMAccountName", "testuser"),
            new LdapAttribute("memberOf", GroupDn),
        };
        var userEntry = new LdapEntry("cn=testuser,ou=people,dc=example,dc=com", userAttrs);

        provider.OnSearchLdap = (filter, attrs) =>
            filter.Contains("sAMAccountName=", StringComparison.Ordinal)
                ? Results(userEntry)
                : Results();

        Assert.True(await provider.IsMemberOfGroupAsync("testuser", "TargetGroup"));
    }

    /// <summary>
    /// The type check runs on the CANDIDATE only. A group the user is in but which no
    /// configured name mentions must not cost a directory read — the group check runs
    /// before the caller has proved anything, and the negative answer is the common
    /// case.
    /// </summary>
    [Fact]
    public async Task ANonCandidateGroup_CostsNoGroupTypeRead()
    {
        var provider = new TestLdapPasswordChangeProvider(
            NullLogger<LdapPasswordChangeProvider>.Instance,
            Options.Create(CreateOptions()),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>());

        var userAttrs = new LdapAttributeSet
        {
            new LdapAttribute("distinguishedName", "cn=testuser,ou=people,dc=example,dc=com"),
            new LdapAttribute("sAMAccountName", "testuser"),
            new LdapAttribute("memberOf", "cn=SomethingElse,ou=groups,dc=example,dc=com"),
        };
        var userEntry = new LdapEntry("cn=testuser,ou=people,dc=example,dc=com", userAttrs);

        var groupTypeReads = 0;
        provider.OnSearchLdap = (filter, attrs) =>
        {
            if (filter.Contains("sAMAccountName=", StringComparison.Ordinal))
                return Results(userEntry);

            if (attrs.Contains("groupType") && !filter.Contains("1.2.840.113556.1.4.1941", StringComparison.Ordinal))
                groupTypeReads++;

            return Results();
        };

        Assert.False(await provider.IsMemberOfGroupAsync("testuser", "TargetGroup"));
        Assert.Equal(0, groupTypeReads);
    }

    private sealed class CapturingLogger : ILogger<LdapPasswordChangeProvider>
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
}
