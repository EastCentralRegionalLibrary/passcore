using System.Linq;
using System.Threading.Tasks;
using Unosquare.PassCore.Common.Exceptions;
using System.Collections.Generic;
using Unosquare.PassCore.Common.Models;

namespace Unosquare.PassCore.Common.Policies;

public class GroupMembershipPolicy : IPasswordPolicy
{
    private readonly List<string> _restrictedGroups;
    private readonly List<string> _allowedGroups;

    public GroupMembershipPolicy(PasswordChangeOptions options)
    {
        _restrictedGroups = options.RestrictedADGroups ?? [];
        _allowedGroups = options.AllowedADGroups ?? [];
    }

    public async Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        if (provider is not IGroupMembershipTester tester)
            return;

        if (_restrictedGroups.Count != 0)
        {
            var restrictedMembershipResults = await Task.WhenAll(
                _restrictedGroups.Select(async group => new
                {
                    Group = group,
                    IsMember = await tester.IsMemberOfGroupAsync(context.Username, group)
                }));

            if (restrictedMembershipResults.Any(x => x.IsMember))
            {
                throw new PasswordPolicyViolationException("User is a member of a restricted group and password change is not permitted.", ApiErrorCode.ChangeNotPermitted);
            }
        }

        if (_allowedGroups.Count != 0)
        {
            var allowedMembershipResults = await Task.WhenAll(
                _allowedGroups.Select(async group => new
                {
                    Group = group,
                    IsMember = await tester.IsMemberOfGroupAsync(context.Username, group)
                }));

            var isMemberOfAnyAllowed = allowedMembershipResults.Any(x => x.IsMember);

            if (!isMemberOfAnyAllowed)
            {
                // Verify if the user is in ANY group if they are not in the allowed list,
                // but for our logic, if allowed groups are defined, they MUST be in one.
                throw new PasswordPolicyViolationException("User is not a member of any allowed group and password change is not permitted.", ApiErrorCode.ChangeNotPermitted);
            }
        }
    }
}
