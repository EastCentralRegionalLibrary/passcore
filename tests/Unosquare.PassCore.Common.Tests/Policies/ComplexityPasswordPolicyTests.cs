using System.Threading.Tasks;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using Unosquare.PassCore.Common.Policies;
using Xunit;

namespace Unosquare.PassCore.Common.Tests.Policies;

public class ComplexityPasswordPolicyTests
{
    [Fact]
    public async Task ValidateAsync_MinimumScoreZero_AlwaysPasses()
    {
        var policy = new ComplexityPasswordPolicy();
        var settings = new ClientSettings { MinimumScore = 0 };
        var context = new PasswordChangeContext("u", "old", "password", settings);

        await policy.ValidateAsync(context, provider: null!);
    }

    [Fact]
    public async Task ValidateAsync_WeakPasswordBelowMinimum_Throws()
    {
        var policy = new ComplexityPasswordPolicy();
        var settings = new ClientSettings { MinimumScore = 3 };
        var context = new PasswordChangeContext("u", "old", "12345", settings);

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => policy.ValidateAsync(context, provider: null!));

        Assert.Equal(ApiErrorCode.MinimumScore, ex.ErrorCode);
    }

    [Fact]
    public async Task ValidateAsync_StrongPassword_Passes()
    {
        var policy = new ComplexityPasswordPolicy();
        var settings = new ClientSettings { MinimumScore = 2 };
        var context = new PasswordChangeContext("u", "old", "Tr0ub4dor&3-correct-horse", settings);

        await policy.ValidateAsync(context, provider: null!);
    }
}
