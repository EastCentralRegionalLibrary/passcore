using System.Linq;
using System.Threading.Tasks;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Policies;

public class GroupMembershipPolicy : IPasswordPolicy
{
    public async Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        if (provider is not IGroupMembershipTester tester)
            return;

        var restrictedGroups = context.ClientSettings.PasswordProviderOptions?.RestrictedAdGroups;
        if (restrictedGroups != null && restrictedGroups.Count != 0)
        {
            var restrictedMembershipResults = await Task.WhenAll(
                restrictedGroups.Select(async group => new
                {
                    Group = group,
                    IsMember = await tester.IsMemberOfGroupAsync(context.Username, group)
                }));

            if (restrictedMembershipResults.Where(x => x.IsMember).Any())
            {
                throw new PasswordPolicyViolationException("User is a member of a restricted group and password change is not permitted.", ApiErrorCode.ChangeNotPermitted);
            }
        }

        var allowedGroups = context.ClientSettings.PasswordProviderOptions?.AllowedAdGroups;
        if (allowedGroups != null && allowedGroups.Count != 0)
        {
            var allowedMembershipResults = await Task.WhenAll(
                allowedGroups.Select(async group => new
                {
                    Group = group,
                    IsMember = await tester.IsMemberOfGroupAsync(context.Username, group)
                }));

            var isMemberOfAnyAllowed = allowedMembershipResults.Where(x => x.IsMember).Any();

            if (!isMemberOfAnyAllowed)
            {
                throw new PasswordPolicyViolationException("User is not a member of any allowed group and password change is not permitted.", ApiErrorCode.ChangeNotPermitted);
            }
        }
    }
}
