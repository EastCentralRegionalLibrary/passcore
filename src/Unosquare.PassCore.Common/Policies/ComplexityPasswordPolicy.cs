using System;
using System.Threading.Tasks;
using Zxcvbn;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Policies;

public class ComplexityPasswordPolicy : IPasswordPolicy
{
    public Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.ClientSettings.MinimumScore > 0 && Core.EvaluatePassword(context.NewPassword).Score < context.ClientSettings.MinimumScore)
        {
            throw new PasswordPolicyViolationException("Password does not meet the minimum score requirement", ApiErrorCode.MinimumScore);
        }

        return Task.CompletedTask;
    }
}
