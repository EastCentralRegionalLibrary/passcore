using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using Unosquare.PassCore.Common.Policies;
using Xunit;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

/// <summary>
/// "Could not determine membership" must never be reported as "not a member".
///
/// <para><c>GroupMembershipPolicy</c> reads <c>IsMemberOfGroupAsync</c> as a
/// <see langword="bool"/>, so the two outcomes are indistinguishable to it. When
/// they are conflated, <c>RestrictedAdGroups</c> — a deny list whose shipped
/// default is <c>Administrators</c>, <c>Domain Admins</c>,
/// <c>Enterprise Admins</c> — <b>fails open</b>: during a partial directory
/// failure, a service-account permissions problem, or a cross-domain timeout,
/// a member of a restricted group is handed a password change. These tests pin
/// the failing-closed behavior, and equally pin that ordinary non-membership is
/// still an ordinary <see langword="false"/>.</para>
/// </summary>
public class GroupMembershipUndeterminedTests
{
    private const string UserDn = "cn=testuser,ou=people,dc=example,dc=com";
    private const string RestrictedGroup = "RestrictedGroup";

    /// <summary>
    /// The core case. The user <b>is</b> a member of the restricted group, nested
    /// beneath a group they hold directly — the directory holds that fact, and the
    /// in-chain search is what would reveal it. That search fails, so membership is
    /// unknown. Reporting "not a member" here is what lets a Domain Admin through.
    /// </summary>
    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public async Task RestrictedMember_WhoseMembershipCannotBeDetermined_DoesNotGetASuccessfulOrNonInfrastructureResponse(
        ErrorDisclosureMode mode)
    {
        var provider = Provider(mode, Directory.WhereNestedLookupFails());

        var error = await Assert.ThrowsAnyAsync<Exception>(
            () => RunRestrictedPolicy(provider));

        // Not "not a member" (which would have let the request proceed), and not a
        // group rejection either — the request is refused as an infrastructure
        // failure, which is what a service-account read failure actually is.
        var wire = ApiErrorMapper.Map(error);
        Assert.Equal(ApiErrorCode.LdapProblem, wire.ErrorCode);
        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, wire.Message);
    }

    /// <summary>
    /// The same undetermined condition, asserted directly on the provider rather
    /// than through the policy: it must not quietly answer <see langword="false"/>.
    /// </summary>
    [Fact]
    public async Task UndeterminedMembership_ThrowsRatherThanReturningNotAMember()
    {
        var provider = Provider(ErrorDisclosureMode.Hardened, Directory.WhereNestedLookupFails());

        await Assert.ThrowsAsync<DirectoryUnavailableException>(
            () => provider.IsMemberOfGroupAsync("testuser", RestrictedGroup));
    }

    /// <summary>
    /// A failed primary-group lookup leaves membership just as unknown as a failed
    /// nested lookup: <c>primaryGroupToken</c> is the authority for the user's
    /// primary group, and <c>memberOf</c> does not list it.
    /// </summary>
    [Fact]
    public async Task PrimaryGroupLookupFailure_IsAlsoUndetermined()
    {
        var provider = Provider(ErrorDisclosureMode.Hardened, Directory.WherePrimaryLookupFails());

        await Assert.ThrowsAsync<DirectoryUnavailableException>(
            () => provider.IsMemberOfGroupAsync("testuser", RestrictedGroup));
    }

    /// <summary>
    /// The other half of the contract, and the one a fail-closed change is most
    /// likely to break: a user who is simply not in the group must still get a
    /// plain "not a member", and the request must proceed. An empty result set is
    /// a completed lookup, not a failure.
    /// </summary>
    [Fact]
    public async Task OrdinaryNonMembership_StillReturnsNotAMemberAndTheRequestProceeds()
    {
        var provider = Provider(ErrorDisclosureMode.Hardened, Directory.WhereEverythingSucceeds());

        Assert.False(await provider.IsMemberOfGroupAsync("testuser", RestrictedGroup));

        // And the deny-list policy lets it through.
        await RunRestrictedPolicy(provider);
    }

    /// <summary>
    /// A match is definitive the moment it is found, so a later lookup failing
    /// cannot turn a confirmed membership into an infrastructure error. Without
    /// this, every restricted-group member during a degraded window would get code
    /// 8 instead of the group rejection.
    /// </summary>
    [Fact]
    public async Task ConfirmedMembership_IsNotDisturbedByALaterLookupFailure()
    {
        // Direct memberOf holds the restricted group; the nested search still fails.
        var provider = Provider(
            ErrorDisclosureMode.Hardened,
            Directory.WhereNestedLookupFails(directGroup: $"cn={RestrictedGroup},ou=groups,dc=example,dc=com"));

        Assert.True(await provider.IsMemberOfGroupAsync("testuser", RestrictedGroup));
    }

    /// <summary>
    /// The operator has to be able to see why requests started failing, so the
    /// undetermined path reports through the shared service-account channel at
    /// Warning rather than being swallowed at Debug.
    /// </summary>
    [Fact]
    public async Task UndeterminedMembership_IsLoggedViaServiceAccountFailureAtWarning()
    {
        var logger = new CapturingLogger();
        var provider = Provider(ErrorDisclosureMode.Hardened, Directory.WhereNestedLookupFails(), logger);

        await Assert.ThrowsAsync<DirectoryUnavailableException>(
            () => provider.IsMemberOfGroupAsync("testuser", RestrictedGroup));

        var entry = Assert.Single(logger.Entries.Where(e => e.EventId.Id == ServiceAccountFailureEventId));
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("LDAP_MATCHING_RULE_IN_CHAIN", entry.Message, StringComparison.Ordinal);
        Assert.Contains("ldap.example.com", entry.Message, StringComparison.Ordinal);
        Assert.NotNull(entry.Exception);
    }

    /// <summary>EventId of <see cref="ServiceAccountFailure"/>, per the registry in <c>PasswordChangeProviderBase</c>.</summary>
    private const int ServiceAccountFailureEventId = 111;

    private static Task RunRestrictedPolicy(IPasswordChangeProvider provider)
    {
        var settings = new ClientSettings
        {
            PasswordProviderOptions = new PasswordProviderOptions
            {
                RestrictedAdGroups = new List<string> { RestrictedGroup },
            },
        };

        return new GroupMembershipPolicy()
            .ValidateAsync(new PasswordChangeContext("testuser", "old", "new", settings), provider);
    }

    /// <summary>
    /// Search behaviors for the three lookups the provider issues, keyed by filter.
    /// Each variant models one directory condition.
    /// </summary>
    private sealed record Directory(string? DirectGroup, bool PrimaryFails, bool NestedFails)
    {
        public static Directory WhereEverythingSucceeds() => new(null, false, false);

        public static Directory WhereNestedLookupFails(string? directGroup = null) =>
            new(directGroup, false, true);

        public static Directory WherePrimaryLookupFails() => new(null, true, false);
    }

    private static TestLdapPasswordChangeProvider Provider(
        ErrorDisclosureMode mode, Directory directory, ILogger<LdapPasswordChangeProvider>? logger = null)
    {
        var options = new LdapPasswordChangeOptions
        {
            LdapHostnames = new[] { "ldap.example.com" },
            LdapPort = 389,
            LdapUsername = "cn=admin,dc=example,dc=com",
            LdapPassword = "secret",
            LdapSearchBase = "dc=example,dc=com",
            LdapSearchFilter = "(sAMAccountName={Username})",
            ErrorDisclosureMode = mode,
        };

        var provider = new TestLdapPasswordChangeProvider(
            logger ?? new CapturingLogger(),
            Options.Create(options),
            Options.Create(new ClientSettings()),
            Array.Empty<IPasswordPolicy>());

        var attributes = new LdapAttributeSet
        {
            new LdapAttribute("distinguishedName", UserDn),
            new LdapAttribute("sAMAccountName", "testuser"),
            new LdapAttribute("primaryGroupID", "1234"),
        };

        if (directory.DirectGroup != null)
            attributes.Add(new LdapAttribute("memberOf", directory.DirectGroup));

        var userEntry = new LdapEntry(UserDn, attributes);

        provider.OnSearchLdap = (filter, _) =>
        {
            if (filter.Contains("sAMAccountName=", StringComparison.Ordinal))
                return Results(userEntry);

            if (filter.Contains("primaryGroupToken=", StringComparison.Ordinal))
            {
                return directory.PrimaryFails
                    ? throw new LdapException("primary group search failed", LdapException.Busy, null)
                    : Results();
            }

            if (filter.Contains("1.2.840.113556.1.4.1941", StringComparison.Ordinal))
            {
                // The nested membership genuinely exists in this directory; this
                // search is simply unable to report it.
                return directory.NestedFails
                    ? throw new LdapException("in-chain search failed", LdapException.Busy, null)
                    : Results();
            }

            return Results();
        };

        return provider;
    }

    private static ILdapSearchResults Results(params LdapEntry[] entries)
    {
        var mock = new Mock<ILdapSearchResults>();
        var remaining = new Queue<LdapEntry>(entries);

        mock.Setup(r => r.HasMore()).Returns(() => remaining.Count > 0);
        mock.Setup(r => r.Next()).Returns(() => remaining.Dequeue());
        return mock.Object;
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
