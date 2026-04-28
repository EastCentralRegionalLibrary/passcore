using System.Threading.Tasks;
using PwnedPasswordsSearch;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;

namespace Unosquare.PassCore.Common.Policies;

public class PwnedPasswordPolicy : IPasswordPolicy
{
    private readonly IPwnedPasswordSearch _pwnedPasswordSearch;
    private readonly bool _isEnabled;

    public PwnedPasswordPolicy(IPwnedPasswordSearch pwnedPasswordSearch, PasswordChangeOptions options)
    {
        _pwnedPasswordSearch = pwnedPasswordSearch;
        _isEnabled = options.EnablePwnedCheck;
    }

    public async Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        if (!_isEnabled)
            return;

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
