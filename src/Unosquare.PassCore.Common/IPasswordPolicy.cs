using System.Threading.Tasks;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Defines a password policy that can be validated.
/// </summary>
public interface IPasswordPolicy
{
    /// <summary>
    /// Validates the password change context against the policy.
    /// </summary>
    /// <param name="context">The password change context.</param>
    /// <param name="provider">The password change provider.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider);
}
