using System.Threading.Tasks;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using Unosquare.PassCore.Common.Policies;
using Xunit;

namespace Unosquare.PassCore.Common.Tests.Policies;

public class DistancePasswordPolicyTests
{
    [Fact]
    public async Task ValidateAsync_MinimumDistanceZero_AlwaysPasses()
    {
        var policy = new DistancePasswordPolicy();
        var settings = new ClientSettings { MinimumDistance = 0 };
        var context = new PasswordChangeContext("u", "same", "same", settings);

        await policy.ValidateAsync(context, provider: null!);
    }

    [Fact]
    public async Task ValidateAsync_PasswordsTooSimilar_Throws()
    {
        var policy = new DistancePasswordPolicy();
        var settings = new ClientSettings { MinimumDistance = 5 };
        var context = new PasswordChangeContext("u", "password1", "password2", settings);

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => policy.ValidateAsync(context, provider: null!));

        Assert.Equal(ApiErrorCode.MinimumDistance, ex.ErrorCode);
    }

    [Fact]
    public async Task ValidateAsync_SufficientlyDifferentPasswords_Passes()
    {
        var policy = new DistancePasswordPolicy();
        var settings = new ClientSettings { MinimumDistance = 5 };
        var context = new PasswordChangeContext("u", "oldsecret", "TotallyDifferent!42", settings);

        await policy.ValidateAsync(context, provider: null!);
    }

    [Fact]
    public async Task ValidateAsync_EmptyOldPassword_DistanceEqualsNewPasswordLength()
    {
        var policy = new DistancePasswordPolicy();
        var settings = new ClientSettings { MinimumDistance = 5 };
        var context = new PasswordChangeContext("u", string.Empty, "abc", settings);

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => policy.ValidateAsync(context, provider: null!));

        Assert.Equal(ApiErrorCode.MinimumDistance, ex.ErrorCode);
    }
}
