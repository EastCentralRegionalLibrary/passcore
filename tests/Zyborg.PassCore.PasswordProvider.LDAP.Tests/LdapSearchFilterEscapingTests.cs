using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using Xunit;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// Every value interpolated into a search filter must be RFC 4515-escaped or
/// validated to a type with no metacharacters.
///
/// <para>The values here are read back from the directory rather than submitted
/// by the caller, which is why they were treated as inert. They are not. RFC
/// 4514 DN string form escapes none of <c>(</c>, <c>)</c> or <c>*</c>, so an
/// account under <c>CN=Smith (Contractor)</c> produces a malformed or
/// structurally altered filter; and a DN that legitimately contains a backslash
/// (RFC 4514 escaping of <c>,</c>, <c>+</c>, <c>"</c> and friends) is read by the
/// server as the start of an RFC 4515 escape sequence. For a deny-list check
/// that yields a <em>wrong answer</em> rather than a clean error.</para>
/// </summary>
public class LdapSearchFilterEscapingTests
{
    private const string ChainFilterPrefix = "(member:1.2.840.113556.1.4.1941:=";

    /// <summary>
    /// One row per metacharacter the task calls out, plus the realistic case that
    /// motivated it. In every case the filter must stay well-formed and its
    /// assertion value must denote exactly the user's DN — nothing wider.
    /// </summary>
    [Theory]
    [InlineData("cn=a(b,ou=people,dc=example,dc=com")]
    [InlineData("cn=a)b,ou=people,dc=example,dc=com")]
    [InlineData("cn=a*b,ou=people,dc=example,dc=com")]
    [InlineData(@"cn=a\,b,ou=people,dc=example,dc=com")]
    [InlineData("cn=Smith (Contractor),ou=people,dc=example,dc=com")]
    [InlineData("cn=plain,ou=people,dc=example,dc=com")]
    public async Task ChainFilter_EscapesTheDistinguishedName_AndMatchesOnlyThatEntry(string userDn)
    {
        var filters = await CapturedFilters(userDn, primaryGroupId: "1234");

        var chainFilter = Assert.Single(filters.Where(f => f.StartsWith(ChainFilterPrefix, StringComparison.Ordinal)));

        Assert.EndsWith(")", chainFilter, StringComparison.Ordinal);

        var assertionValue = chainFilter[ChainFilterPrefix.Length..^1];

        AssertNoUnescapedMetacharacters(assertionValue);

        // The escaped value must denote the DN exactly: unescaping it round-trips
        // to the original. A filter that matched more than this entry (a stray '*'
        // turning it into a substring match) or less than it (a mangled escape)
        // would fail here.
        Assert.Equal(userDn, UnescapeRfc4515(assertionValue));
    }

    /// <summary>
    /// The <c>primaryGroupToken</c> filter carries a RID. It is validated as an
    /// integer rather than escaped: an integer has nothing to escape, and the
    /// attribute is meaningless if it is not one.
    /// </summary>
    [Theory]
    [InlineData("1234")]
    [InlineData("513")]
    public async Task PrimaryGroupFilter_CarriesTheValidatedRid(string primaryGroupId)
    {
        var filters = await CapturedFilters("cn=u,ou=people,dc=example,dc=com", primaryGroupId);

        var primaryFilter = Assert.Single(filters.Where(f => f.Contains("primaryGroupToken", StringComparison.Ordinal)));
        Assert.Equal($"(primaryGroupToken={primaryGroupId})", primaryFilter);
    }

    /// <summary>
    /// A <c>primaryGroupID</c> that is not an integer must never reach a filter.
    /// Interpolating it would put attacker-influenced-or-corrupt directory data
    /// straight into the filter's structure.
    /// </summary>
    [Theory]
    [InlineData("not-a-number")]
    [InlineData("1234)(objectClass=*")]
    [InlineData("*")]
    [InlineData("")]
    [InlineData(" 513")]
    [InlineData("0x200")]
    [InlineData("-1")]
    public async Task NonNumericPrimaryGroupId_NeverReachesAFilter(string primaryGroupId)
    {
        var logger = new CapturingLogger();
        var provider = Provider("cn=u,ou=people,dc=example,dc=com", primaryGroupId, logger, out var filters);

        // An unresolvable primary group leaves membership undetermined, so the
        // call fails closed rather than answering from an incomplete picture.
        // (An empty attribute is simply "no primary group" and is not a failure.)
        if (primaryGroupId.Length == 0)
        {
            Assert.False(await provider.IsMemberOfGroupAsync("u", "RestrictedGroup"));
        }
        else
        {
            await Assert.ThrowsAsync<DirectoryUnavailableException>(
                () => provider.IsMemberOfGroupAsync("u", "RestrictedGroup"));
        }

        Assert.DoesNotContain(filters, f => f.Contains("primaryGroupToken", StringComparison.Ordinal));
    }

    /// <summary>
    /// The malformed-RID path has to be visible to an operator: it is a
    /// directory-data problem that starts refusing requests.
    /// </summary>
    [Fact]
    public async Task NonNumericPrimaryGroupId_IsLoggedAtWarningNamingTheAccount()
    {
        var logger = new CapturingLogger();
        var provider = Provider("cn=u,ou=people,dc=example,dc=com", "not-a-number", logger, out _);

        await Assert.ThrowsAsync<DirectoryUnavailableException>(
            () => provider.IsMemberOfGroupAsync("u", "RestrictedGroup"));

        var entry = Assert.Single(logger.Entries.Where(e => e.EventId.Id == 106));
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("not-a-number", entry.Message, StringComparison.Ordinal);
        Assert.Contains("cn=u,ou=people,dc=example,dc=com", entry.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The user-lookup filter is the one that was already escaped, and it must
    /// stay that way — including the domain component appended from configuration.
    /// </summary>
    [Theory]
    [InlineData("jdoe", "ex(ample.com")]
    [InlineData("jdoe", "ex*ample.com")]
    [InlineData("jdoe", @"ex\ample.com")]
    [InlineData("jdoe", "example.com")]
    public void SanitizeUsername_WithAMetacharacterInTheConfiguredDomain_StillProducesAnInertValue(
        string username, string defaultDomain)
    {
        AssertNoUnescapedMetacharacters(
            LdapPasswordChangeProvider.SanitizeUsername(username, defaultDomain));
    }

    /// <summary>
    /// Asserts the RFC 4515 §3 rule for an assertion value: no bare <c>*</c>,
    /// <c>(</c>, <c>)</c> or NUL, and every backslash introducing a two-hex-digit
    /// escape.
    /// </summary>
    private static void AssertNoUnescapedMetacharacters(string value)
    {
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            Assert.True(
                c is not ('(' or ')' or '*' or '\0'),
                $"Unescaped metacharacter '{c}' at index {i} in \"{value}\"");

            if (c != '\\') continue;

            Assert.True(
                i + 2 < value.Length && Uri.IsHexDigit(value[i + 1]) && Uri.IsHexDigit(value[i + 2]),
                $"Backslash at index {i} in \"{value}\" does not introduce a valid \\XX escape");
            i += 2;
        }
    }

    /// <summary>Reverses <c>EscapeLdapSearchFilterValue</c>, so a filter value can be compared to what it denotes.</summary>
    private static string UnescapeRfc4515(string value)
    {
        var builder = new StringBuilder(value.Length);

        for (var i = 0; i < value.Length; i++)
        {
            if (value[i] == '\\')
            {
                builder.Append((char)Convert.ToInt32(value.Substring(i + 1, 2), 16));
                i += 2;
                continue;
            }

            builder.Append(value[i]);
        }

        return builder.ToString();
    }

    private static async Task<List<string>> CapturedFilters(string userDn, string primaryGroupId)
    {
        var provider = Provider(userDn, primaryGroupId, NullLogger<LdapPasswordChangeProvider>.Instance, out var filters);

        // No group matches; the point is which filters were issued along the way.
        Assert.False(await provider.IsMemberOfGroupAsync("u", "NoSuchGroup"));

        return filters;
    }

    private static TestLdapPasswordChangeProvider Provider(
        string userDn,
        string primaryGroupId,
        ILogger<LdapPasswordChangeProvider> logger,
        out List<string> filters)
    {
        var options = new LdapPasswordChangeOptions
        {
            LdapHostnames = new[] { "ldap.example.com" },
            LdapPort = 389,
            LdapUsername = "cn=admin,dc=example,dc=com",
            LdapPassword = "secret",
            LdapSearchBase = "dc=example,dc=com",
            LdapSearchFilter = "(sAMAccountName={Username})",
        };

        var provider = new TestLdapPasswordChangeProvider(
            logger,
            Options.Create(options),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>());

        var attributes = new LdapAttributeSet
        {
            new LdapAttribute("distinguishedName", userDn),
            new LdapAttribute("sAMAccountName", "u"),
        };

        if (primaryGroupId.Length > 0)
            attributes.Add(new LdapAttribute("primaryGroupID", primaryGroupId));

        var userEntry = new LdapEntry(userDn, attributes);

        var captured = new List<string>();
        filters = captured;

        provider.OnSearchLdap = (filter, _) =>
        {
            captured.Add(filter);

            var results = new Mock<ILdapSearchResults>();
            if (filter.Contains("sAMAccountName=", StringComparison.Ordinal))
            {
                var remaining = new Queue<LdapEntry>(new[] { userEntry });
                results.Setup(r => r.HasMore()).Returns(() => remaining.Count > 0);
                results.Setup(r => r.Next()).Returns(() => remaining.Dequeue());
            }
            else
            {
                results.Setup(r => r.HasMore()).Returns(false);
            }

            return results.Object;
        };

        return provider;
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
