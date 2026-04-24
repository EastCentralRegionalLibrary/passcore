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
    Task<bool> IsMemberOfGroupAsync(string username, string groupName);
}
