using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Models;
using Unosquare.PassCore.Common.Policies;
using Xunit;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// Group evaluation runs before credential verification, on any POST with any
/// username, on an endpoint with no rate limiting. It used to re-resolve the user
/// from scratch for every configured group name — with the shipped three
/// restricted groups, three binds and three searches per unauthenticated request.
///
/// <para>These tests count the directory work a single request performs. They are
/// about load, not correctness: the membership outcomes themselves are pinned by
/// <c>GroupMembershipParityTests</c> and <c>GroupMembershipUndeterminedTests</c>,
/// which are unchanged.</para>
/// </summary>
public class PreAuthenticationDirectoryLoadTests
{
    private const string UserDn = "cn=testuser,ou=people,dc=example,dc=com";

    /// <summary>The shipped default deny list.</summary>
    private static readonly List<string> ShippedRestrictedGroups =
        new() { "Administrators", "Domain Admins", "Enterprise Admins" };

    [Fact]
    public async Task TheUserIsResolvedOncePerRequest_NotOncePerConfiguredGroup()
    {
        var provider = Provider(out var filters);

        await new GroupMembershipPolicy().ValidateAsync(Context(ShippedRestrictedGroups), provider);

        var userLookups = filters.Count(f => f.Contains("sAMAccountName=", StringComparison.Ordinal));

        Assert.Equal(1, userLookups);

        // Sanity check that the configuration under test would previously have cost
        // one resolution per name, so the assertion above is not trivially true.
        Assert.Equal(3, ShippedRestrictedGroups.Count);

        // And the supplementary lookups are likewise not repeated per group name.
        Assert.Equal(1, filters.Count(f => f.Contains("1.2.840.113556.1.4.1941", StringComparison.Ordinal)));

        // One bind: the membership path is consolidated onto one service-account connection,
        // so the floor for this configuration is exactly one bind.
        Assert.Equal(1, provider.Binds);
    }

    /// <summary>
    /// With both lists configured the policy asks twice — restricted, then allowed —
    /// but the user is still resolved only once for the request.
    /// </summary>
    [Fact]
    public async Task WithBothListsConfigured_TheUserIsStillResolvedOnce()
    {
        var provider = Provider(out var filters);

        var settings = new ClientSettings
        {
            PasswordProviderOptions = new PasswordProviderOptions
            {
                RestrictedAdGroups = ShippedRestrictedGroups,
                AllowedAdGroups = new List<string> { "PasswordResetUsers", "Staff" },
            },
        };

        // testuser is in DirectGroup only: not restricted, and not allowed either,
        // so this refuses — after a single resolution.
        await Assert.ThrowsAnyAsync<Exception>(
            () => new GroupMembershipPolicy().ValidateAsync(
                new PasswordChangeContext("testuser", "old", "new", settings), provider));

        Assert.Equal(1, filters.Count(f => f.Contains("sAMAccountName=", StringComparison.Ordinal)));
    }

    /// <summary>
    /// Nothing configured must cost nothing. This check runs before the caller has
    /// proved anything, so a deployment that configures neither list must not hand
    /// an unauthenticated request any directory work at all.
    /// </summary>
    [Fact]
    public async Task WithNoGroupsConfigured_TheDirectoryIsNotQueriedAtAll()
    {
        var provider = Provider(out var filters);

        var settings = new ClientSettings { PasswordProviderOptions = new PasswordProviderOptions() };
        await new GroupMembershipPolicy().ValidateAsync(
            new PasswordChangeContext("testuser", "old", "new", settings), provider);

        Assert.Empty(filters);
        Assert.Equal(0, provider.Binds);
    }

    /// <summary>
    /// A direct match must still skip the supplementary searches. Resolving once per
    /// request must not turn into "always run everything".
    /// </summary>
    [Fact]
    public async Task ADirectMatch_StillSkipsTheSupplementaryLookups()
    {
        var provider = Provider(out var filters);

        var settings = new ClientSettings
        {
            PasswordProviderOptions = new PasswordProviderOptions
            {
                RestrictedAdGroups = new List<string> { "DirectGroup" },
            },
        };

        await Assert.ThrowsAnyAsync<Exception>(
            () => new GroupMembershipPolicy().ValidateAsync(
                new PasswordChangeContext("testuser", "old", "new", settings), provider));

        Assert.Equal(1, filters.Count(f => f.Contains("sAMAccountName=", StringComparison.Ordinal)));
        Assert.DoesNotContain(filters, f => f.Contains("1.2.840.113556.1.4.1941", StringComparison.Ordinal));
        Assert.DoesNotContain(filters, f => f.Contains("primaryGroupToken", StringComparison.Ordinal));
    }

    /// <summary>
    /// The minimum-length lookup is domain-wide, so a burst of unauthenticated
    /// requests collapses onto one directory read rather than one per request.
    /// </summary>
    [Fact]
    public async Task TheMinimumLengthLookupIsNotRepeatedForEveryRequest()
    {
        var provider = ProviderWithDomainPolicy(out var filters, minPwdLength: 14);

        for (var i = 0; i < 5; i++)
            Assert.Equal(14, await provider.GetMinimumLengthAsync());

        // The rootDSE probe runs once for five requests rather than once each.
        Assert.Equal(1, filters.Count(f => f.Contains("defaultNamingContext", StringComparison.Ordinal)));
    }

    /// <summary>
    /// A lookup that cannot produce a value is deliberately not cached: caching it
    /// would suppress the operator-actionable warning for the whole TTL.
    /// </summary>
    [Fact]
    public async Task AFailingMinimumLengthLookupIsRetriedRatherThanCached()
    {
        var provider = Provider(out var filters);

        for (var i = 0; i < 3; i++)
            await provider.GetMinimumLengthAsync();

        Assert.Equal(3, filters.Count(f => f.Contains("defaultNamingContext", StringComparison.Ordinal)));
    }

    /// <summary>
    /// As <see cref="Provider"/>, but the directory answers the rootDSE and domain
    /// naming context probes, so the minimum length actually resolves.
    /// </summary>
    private static CountingLdapProvider ProviderWithDomainPolicy(out List<string> filters, int minPwdLength)
    {
        var provider = Provider(out var seen);
        filters = seen;

        var rootDse = new LdapEntry(
            string.Empty,
            new LdapAttributeSet { new LdapAttribute("defaultNamingContext", "dc=example,dc=com") });

        var domainNc = new LdapEntry(
            "dc=example,dc=com",
            new LdapAttributeSet
            {
                new LdapAttribute("minPwdLength", minPwdLength.ToString(System.Globalization.CultureInfo.InvariantCulture)),
            });

        provider.OnSearchLdap = (filter, attrs) =>
        {
            seen.Add(Record(filter, attrs));

            var entry = attrs.Contains("defaultNamingContext") ? rootDse
                : attrs.Contains("minPwdLength") ? domainNc
                : null;

            var results = new Mock<ILdapSearchResults>();
            if (entry is null)
            {
                results.Setup(r => r.HasMoreAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);
            }
            else
            {
                var remaining = new Queue<LdapEntry>(new[] { entry });
                results.Setup(r => r.HasMoreAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => remaining.Count > 0);
                results.Setup(r => r.NextAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => remaining.Dequeue());
            }

            return results.Object;
        };

        return provider;
    }

    /// <summary>Filter plus requested attributes, so two probes sharing a filter stay distinguishable.</summary>
    private static string Record(string filter, IEnumerable<string> attributes) =>
        $"{filter} [{string.Join(",", attributes)}]";

    private static PasswordChangeContext Context(List<string> restrictedGroups) =>
        new(
            "testuser", "old", "new",
            new ClientSettings
            {
                PasswordProviderOptions = new PasswordProviderOptions { RestrictedAdGroups = restrictedGroups },
            });

    /// <summary>
    /// A provider over a directory holding one account, <c>testuser</c>, a member of
    /// <c>DirectGroup</c> and nothing else. <paramref name="filters"/> collects every
    /// search filter issued and <paramref name="bindCount"/> counts service-account
    /// binds, in issue order.
    /// </summary>
    private static CountingLdapProvider Provider(out List<string> filters)
    {
        var options = new LdapPasswordChangeOptions
        {
            LdapHostnames = new[] { "ldap.example.com" },
            LdapPort = 636,
        LdapSecureSocketLayer = true,
            LdapUsername = "cn=admin,dc=example,dc=com",
            LdapPassword = "secret",
            LdapSearchBase = "dc=example,dc=com",
            LdapSearchFilter = "(sAMAccountName={Username})",
        };

        var provider = new CountingLdapProvider(
            NullLogger<LdapPasswordChangeProvider>.Instance,
            Options.Create(options),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>());

        var userEntry = new LdapEntry(
            UserDn,
            new LdapAttributeSet
            {
                new LdapAttribute("distinguishedName", UserDn),
                new LdapAttribute("sAMAccountName", "testuser"),
                new LdapAttribute("memberOf", "cn=DirectGroup,ou=groups,dc=example,dc=com"),
            });

        var seen = new List<string>();
        filters = seen;

        provider.OnSearchLdap = (filter, attrs) =>
        {
            seen.Add(Record(filter, attrs));

            var results = new Mock<ILdapSearchResults>();
            if (filter.Contains("sAMAccountName=testuser", StringComparison.Ordinal))
            {
                var remaining = new Queue<LdapEntry>(new[] { userEntry });
                results.Setup(r => r.HasMoreAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => remaining.Count > 0);
                results.Setup(r => r.NextAsync(It.IsAny<CancellationToken>())).ReturnsAsync(() => remaining.Dequeue());
            }
            else
            {
                results.Setup(r => r.HasMoreAsync(It.IsAny<CancellationToken>())).ReturnsAsync(false);
            }

            return results.Object;
        };

        return provider;
    }

    /// <summary>Adds bind counting on top of the shared test provider.</summary>
    private sealed class CountingLdapProvider : TestLdapPasswordChangeProvider
    {
        public CountingLdapProvider(
            Microsoft.Extensions.Logging.ILogger<LdapPasswordChangeProvider> logger,
            IOptions<LdapPasswordChangeOptions> options,
            IOptions<ClientSettings> clientSettings,
            IEnumerable<IPasswordPolicy> policies)
            : base(logger, options, clientSettings, policies)
        {
        }

        public int Binds { get; private set; }

        internal override async Task<LdapConnection> BindAsServiceAccount(string? correlationId = null)
        {
            Binds++;
            return await base.BindAsServiceAccount(correlationId);
        }
    }
}
