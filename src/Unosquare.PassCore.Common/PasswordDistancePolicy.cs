using System;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Policy for validating the minimum distance between old and new passwords.
/// </summary>
public class PasswordDistancePolicy : IPasswordPolicy
{
    public void Validate(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(provider);

        if (context.ClientSettings?.MinimumDistance > 0 &&
            provider.MeasureNewPasswordDistance(context.CurrentPassword, context.NewPassword) < context.ClientSettings.MinimumDistance)
        {
            throw new PasswordPolicyViolationException(ApiErrorCode.MinimumDistance, "The distance between the old and new password is too short.");
        }
    }
}
