using System.Collections.Generic;
using System.Threading.Tasks;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Defines a provider that can test for user group membership.
/// </summary>
public interface IGroupMembershipTester
{
    /// <summary>
    /// Checks if a user is a member of a specific group.
    /// </summary>
    /// <param name="username">The username to check.</param>
    /// <param name="groupName">The name of the group.</param>
    /// <returns>A task representing the asynchronous operation, containing true if the user is a member, otherwise false.</returns>
    /// <remarks>
    /// A negative answer means "determined not to be a member". A membership that
    /// could not be determined throws rather than answering <see langword="false"/>,
    /// so that a deny list fails closed.
    /// </remarks>
    Task<bool> IsMemberOfGroupAsync(string username, string groupName);
}

/// <summary>
/// An optional companion to <see cref="IGroupMembershipTester"/> for providers that
/// can resolve a user's membership once and then answer any number of group names
/// from that single resolution.
/// </summary>
/// <remarks>
/// <para>This exists because every configured group name used to cost a full
/// resolution: <c>GroupMembershipPolicy</c> called
/// <see cref="IGroupMembershipTester.IsMemberOfGroupAsync"/> once per name, and each
/// call re-resolved the user from scratch. With the shipped three restricted groups
/// that is three resolutions per request, all before the caller has proved anything,
/// on an endpoint with no rate limiting.</para>
/// <para>It is deliberately a separate interface rather than a member of
/// <see cref="IGroupMembershipTester"/>. Adding a member there — even one with a
/// default implementation — would change what every existing implementer and test
/// double presents, and a mocking framework auto-implements interface members
/// regardless of whether they have a default body. Keeping it separate means a
/// provider opts in and everything else is untouched: callers fall back to the
/// per-group path exactly as before.</para>
/// </remarks>
public interface IGroupMembershipResolver
{
    /// <summary>Resolves the user's group membership once.</summary>
    /// <param name="username">The username whose membership to resolve.</param>
    Task<IResolvedGroupMembership> ResolveMembershipAsync(string username);
}

/// <summary>
/// A single user's group membership, already resolved, so that testing further
/// group names costs no additional directory work.
/// </summary>
public interface IResolvedGroupMembership
{
    /// <summary>
    /// Reports whether the user belongs to any of <paramref name="groupNames"/>.
    /// </summary>
    /// <remarks>
    /// Carries the same contract as <see cref="IGroupMembershipTester.IsMemberOfGroupAsync"/>:
    /// a match is definitive, and <see langword="false"/> means "determined to belong to
    /// none of them". If none matched and the membership could not be fully determined,
    /// this throws rather than answering <see langword="false"/>.
    /// </remarks>
    /// <param name="groupNames">The group names to test. An empty collection is
    /// <see langword="false"/> and performs no work.</param>
    Task<bool> IsMemberOfAnyAsync(IReadOnlyCollection<string> groupNames);
}

/// <summary>
/// The fallback used when a provider does not implement
/// <see cref="IGroupMembershipResolver"/>: resolves nothing up front and asks the
/// per-group method for each name, which is what every caller did before.
/// </summary>
internal sealed class PerGroupResolvedMembership : IResolvedGroupMembership
{
    private readonly IGroupMembershipTester _tester;
    private readonly string _username;

    public PerGroupResolvedMembership(IGroupMembershipTester tester, string username)
    {
        _tester = tester;
        _username = username;
    }

    public async Task<bool> IsMemberOfAnyAsync(IReadOnlyCollection<string> groupNames)
    {
        if (groupNames is null || groupNames.Count == 0)
            return false;

        foreach (var groupName in groupNames)
        {
            if (await _tester.IsMemberOfGroupAsync(_username, groupName).ConfigureAwait(false))
                return true;
        }

        return false;
    }
}
