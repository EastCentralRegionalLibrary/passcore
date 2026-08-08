using System;
using System.Threading.Tasks;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Policies;

/// <summary>
/// Policy to enforce minimum password length requirements.
/// </summary>
public class LengthPasswordPolicy : IPasswordPolicy
{
    /// <inheritdoc />
    public async Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(provider);

        // Kept even though PasswordChangeProviderBase now implements the
        // interface for every shipped provider. IPasswordChangeProvider is
        // public and can be implemented without deriving from that base, so
        // removing this check would turn a third-party provider into a cast
        // failure at request time.
        if (provider is IPasswordLengthRequirement requirement)
        {
            var minLength = await requirement.GetMinimumLengthAsync();
            if (context.NewPassword.Length < minLength)
            {
                // Deliberately does not say "domain": this policy is
                // provider-agnostic and runs in front of directories that have no
                // domain at all. The numeral matters — the AD smoke test asserts
                // the message names the minimum that was actually read, which is
                // what distinguishes a working lookup from the shared fallback.
                throw new PasswordPolicyViolationException($"The new password does not meet the minimum length requirement of {minLength} characters.", ApiErrorCode.ComplexPassword);
            }
        }
    }
}
