using System.Threading.Tasks;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Policies;

public class LengthPasswordPolicy : IPasswordPolicy
{
    public async Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        if (provider is IPasswordLengthRequirement requirement)
        {
            var minLength = await requirement.GetMinimumLengthAsync();
            if (context.NewPassword.Length < minLength)
            {
                throw new PasswordPolicyViolationException($"The new password does not meet the Active Directory domain minimum password length requirement of {minLength} characters.", ApiErrorCode.ComplexPassword);
            }
        }
    }
}
