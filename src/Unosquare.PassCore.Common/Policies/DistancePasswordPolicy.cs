using System;
using System.Threading.Tasks;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Policies;

/// <summary>
/// Policy to enforce minimum Levenshtein distance between current and new passwords.
/// </summary>
public class DistancePasswordPolicy : IPasswordPolicy
{
    /// <inheritdoc />
    public Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.ClientSettings.MinimumDistance > 0)
        {
            var distance = MeasureNewPasswordDistance(context.CurrentPassword, context.NewPassword, context.ClientSettings.MinimumDistance);
            if (distance < context.ClientSettings.MinimumDistance)
            {
                throw new PasswordPolicyViolationException("Password does not meet the minimum distance requirement", ApiErrorCode.MinimumDistance);
            }
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Measures the Levenshtein distance between two password strings with threshold-aware early exit and bounded O(min(n, m)) memory.
    /// </summary>
    /// <param name="currentPassword">The current password.</param>
    /// <param name="newPassword">The new password.</param>
    /// <param name="threshold">The distance threshold for early exit.</param>
    /// <returns>The calculated Levenshtein distance or threshold if bound is reached.</returns>
    internal static int MeasureNewPasswordDistance(string currentPassword, string newPassword, int threshold = int.MaxValue)
    {
        ArgumentNullException.ThrowIfNull(currentPassword);
        ArgumentNullException.ThrowIfNull(newPassword);

        var n = currentPassword.Length;
        var m = newPassword.Length;

        if (n == 0) return m;
        if (m == 0) return n;

        var lengthDiff = Math.Abs(n - m);
        if (lengthDiff >= threshold)
        {
            return lengthDiff;
        }

        var s1 = currentPassword;
        var s2 = newPassword;
        if (n < m)
        {
            s1 = newPassword;
            s2 = currentPassword;
            n = s1.Length;
            m = s2.Length;
        }

        var row = new int[m + 1];

        for (var j = 0; j <= m; j++)
        {
            row[j] = j;
        }

        for (var i = 1; i <= n; i++)
        {
            var prevDiagonal = row[0];
            row[0] = i;
            var minInRow = row[0];

            var char1 = s1[i - 1];

            for (var j = 1; j <= m; j++)
            {
                var temp = row[j];
                var cost = (char1 == s2[j - 1]) ? 0 : 1;

                var distance = Math.Min(
                    Math.Min(row[j] + 1, row[j - 1] + 1),
                    prevDiagonal + cost);

                row[j] = distance;
                prevDiagonal = temp;

                if (distance < minInRow)
                {
                    minInRow = distance;
                }
            }

            if (minInRow >= threshold)
            {
                return minInRow;
            }
        }

        return row[m];
    }
}
