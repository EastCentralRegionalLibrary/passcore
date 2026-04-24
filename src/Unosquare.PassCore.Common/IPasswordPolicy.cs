namespace Unosquare.PassCore.Common;

/// <summary>
/// Defines an interface for password policies.
/// </summary>
public interface IPasswordPolicy
{
    /// <summary>
    /// Validates the password change context against the policy.
    /// </summary>
    /// <param name="context">The password change context.</param>
    /// <param name="provider">The password change provider (for helper methods like distance).</param>
    void Validate(PasswordChangeContext context, IPasswordChangeProvider provider);
}
