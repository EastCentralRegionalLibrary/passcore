using System.Linq;
using System.Threading.Tasks;

namespace Unosquare.PassCore.Common.Policies;

public class GroupMembershipPolicy : IPasswordPolicy
{
    public async Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        if (provider is not IGroupMembershipTester tester)
            return;

        var disclosureMode = provider is IDisclosurePosture posture ? posture.ErrorDisclosureMode : ErrorDisclosureMode.Hardened;

        var restrictedGroups = context.ClientSettings.PasswordProviderOptions?.RestrictedAdGroups;
        if (restrictedGroups != null && restrictedGroups.Count != 0)
        {
            var restrictedMembershipResults = await Task.WhenAll(
                restrictedGroups.Select(async group => new
                {
                    Group = group,
                    IsMember = await tester.IsMemberOfGroupAsync(context.Username, group)
                }));

            if (restrictedMembershipResults.Any(x => x.IsMember))
            {
                throw DirectoryErrorTranslator.CreateGroupRejectionError(disclosureMode);
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

            var isMemberOfAnyAllowed = allowedMembershipResults.Any(x => x.IsMember);

            if (!isMemberOfAnyAllowed)
            {
                throw DirectoryErrorTranslator.CreateGroupRejectionError(disclosureMode);
            }
        }
    }
}
