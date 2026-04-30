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
            var distance = MeasureNewPasswordDistance(context.CurrentPassword, context.NewPassword);
            if (distance < context.ClientSettings.MinimumDistance)
            {
                throw new PasswordPolicyViolationException("Password does not meet the minimum distance requirement", ApiErrorCode.MinimumDistance);
            }
        }

        return Task.CompletedTask;
    }

    private static int MeasureNewPasswordDistance(string currentPassword, string newPassword)
    {
        var n = currentPassword.Length;
        var m = newPassword.Length;
        var d = new int[n + 1, m + 1];

        if (n == 0) return m;
        if (m == 0) return n;

        for (var i = 0; i <= n; d[i, 0] = i++) { }
        for (var j = 0; j <= m; d[0, j] = j++) { }

        for (var i = 1; i <= n; i++)
        {
            for (var j = 1; j <= m; j++)
            {
                var cost = (newPassword[j - 1] == currentPassword[i - 1]) ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
            }
        }

        return d[n, m];
    }
}
