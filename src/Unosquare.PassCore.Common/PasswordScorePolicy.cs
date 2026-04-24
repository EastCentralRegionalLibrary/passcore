using System;
using Zxcvbn;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Policy for validating the minimum score (entropy) of the new password using Zxcvbn.
/// </summary>
public class PasswordScorePolicy : IPasswordPolicy
{
    public void Validate(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.ClientSettings?.MinimumScore > 0 &&
            Core.EvaluatePassword(context.NewPassword).Score < context.ClientSettings.MinimumScore)
        {
            throw new PasswordPolicyViolationException(ApiErrorCode.MinimumScore, "The new password is not complex enough.");
        }
    }
}
