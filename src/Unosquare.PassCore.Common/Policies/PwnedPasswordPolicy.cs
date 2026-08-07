using System;
using System.Threading.Tasks;
using PwnedPasswordsSearch;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common.Policies;

/// <summary>
/// Policy to check if the new password has been compromised (leaked/pwned).
/// </summary>
public class PwnedPasswordPolicy : IPasswordPolicy
{
    private readonly IPwnedPasswordSearch _pwnedPasswordSearch;

    /// <summary>
    /// Initializes a new instance of the <see cref="PwnedPasswordPolicy"/> class.
    /// </summary>
    /// <param name="pwnedPasswordSearch">The pwned password search service.</param>
    public PwnedPasswordPolicy(IPwnedPasswordSearch pwnedPasswordSearch)
    {
        _pwnedPasswordSearch = pwnedPasswordSearch;
    }

    /// <inheritdoc />
    public async Task ValidateAsync(PasswordChangeContext context, IPasswordChangeProvider provider)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (context.ClientSettings.EnablePwnedPasswordCheck == false)
        {
            return;
        }

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
            // Fail closed with a clean surface message: the Generic code renders
            // its message verbatim in the UI, so the HIBP client's exception text
            // must stay out of it. Full detail reaches logs via the inner
            // exception (the base class logs policy failures with correlation ID).
            throw new PasswordPolicyViolationException(
                UnavailableMessage(context.CorrelationId), ApiErrorCode.Generic, ex);
        }
        catch (PwnedPasswordsSearchException ex)
        {
            throw new PasswordPolicyViolationException(
                UnavailableMessage(context.CorrelationId), ApiErrorCode.Generic, ex);
        }
    }

    private static string UnavailableMessage(string? correlationId) =>
        $"The compromised-password check could not be completed. Please try again later (ref: {correlationId ?? "n/a"})";
}
