using System;
using System.Threading.Tasks;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Policies;

public class DistancePasswordPolicy : IPasswordPolicy
{
    public Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.ClientSettings.MinimumDistance > 0)
        {
            var distance = provider.MeasureNewPasswordDistance(context.CurrentPassword, context.NewPassword);
            if (distance < context.ClientSettings.MinimumDistance)
            {
                throw new PasswordPolicyViolationException("Password does not meet the minimum distance requirement", ApiErrorCode.MinimumDistance);
            }
        }

        return Task.CompletedTask;
    }
}
