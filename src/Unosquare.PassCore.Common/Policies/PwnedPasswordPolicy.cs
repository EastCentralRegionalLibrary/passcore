using System.Threading.Tasks;
using PwnedPasswordsSearch;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Policies;

public class PwnedPasswordPolicy : IPasswordPolicy
{
    private readonly IPwnedPasswordSearch _pwnedPasswordSearch;

    public PwnedPasswordPolicy(IPwnedPasswordSearch pwnedPasswordSearch)
    {
        _pwnedPasswordSearch = pwnedPasswordSearch;
    }

    public async Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        // This policy is generally applicable if pwned check is enabled in any way,
        // but here we check the new password against the pwned database.
        try
        {
            if (await _pwnedPasswordSearch.IsPwnedPasswordAsync(context.NewPassword))
            {
                throw new PasswordPolicyViolationException("The password is a known compromised password and is not allowed.", ApiErrorCode.PwnedPassword);
            }
        }
        catch (PwnedPasswordsApiException ex)
        {
            throw new PasswordPolicyViolationException($"Error during Pwned Password API check: {ex.Message}", ApiErrorCode.Generic);
        }
        catch (PwnedPasswordsSearchException ex)
        {
            throw new PasswordPolicyViolationException($"Unexpected error during Pwned Password search: {ex.Message}", ApiErrorCode.Generic);
        }
    }
}
