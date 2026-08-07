using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Unosquare.PassCore.Common.Policies;

/// <summary>
/// Policy to restrict or allow password change based on user group membership.
/// </summary>
public class GroupMembershipPolicy : IPasswordPolicy
{
    /// <inheritdoc />
    public async Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(provider);

        if (provider is not IGroupMembershipTester tester)
            return;

        var disclosureMode = provider is IDisclosurePosture posture ? posture.ErrorDisclosureMode : ErrorDisclosureMode.Hardened;

        var restrictedGroups = context.ClientSettings.PasswordProviderOptions?.RestrictedAdGroups;
        var allowedGroups = context.ClientSettings.PasswordProviderOptions?.AllowedAdGroups;

        var hasRestricted = restrictedGroups is { Count: > 0 };
        var hasAllowed = allowedGroups is { Count: > 0 };

        // Nothing configured means nothing to ask the directory. This runs before
        // the caller has proved anything, so a deployment that configures neither
        // list must not pay for a lookup at all.
        if (!hasRestricted && !hasAllowed)
            return;

        // Resolved once, then tested against both lists. Previously each configured
        // group name cost its own full resolution of the user. A provider that does
        // not opt into IGroupMembershipResolver keeps the old per-group path.
        var membership = provider is IGroupMembershipResolver resolver
            ? await resolver.ResolveMembershipAsync(context.Username).ConfigureAwait(false)
            : new PerGroupResolvedMembership(tester, context.Username);

        // Restricted before allowed, unchanged: a member of a restricted group is
        // rejected regardless of what the allowed list says.
        if (hasRestricted && await membership.IsMemberOfAnyAsync(AsCollection(restrictedGroups)).ConfigureAwait(false))
            throw DirectoryErrorTranslator.CreateGroupRejectionError(disclosureMode);

        if (hasAllowed && !await membership.IsMemberOfAnyAsync(AsCollection(allowedGroups)).ConfigureAwait(false))
            throw DirectoryErrorTranslator.CreateGroupRejectionError(disclosureMode);
    }

    private static IReadOnlyCollection<string> AsCollection(IReadOnlyCollection<string>? groups) =>
        groups ?? System.Array.Empty<string>();
}
