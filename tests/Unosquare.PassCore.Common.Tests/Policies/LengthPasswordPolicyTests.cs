using System.Threading.Tasks;
using Moq;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using Unosquare.PassCore.Common.Policies;
using Xunit;

namespace Unosquare.PassCore.Common.Tests.Policies;

public class LengthPasswordPolicyTests
{
    [Fact]
    public async Task ValidateAsync_ProviderDoesNotAdvertiseRequirement_Passes()
    {
        var policy = new LengthPasswordPolicy();
        var provider = new Mock<IPasswordChangeProvider>();
        var context = new PasswordChangeContext("u", "old", "a", new ClientSettings());

        await policy.ValidateAsync(context, provider.Object);
    }

    [Fact]
    public async Task ValidateAsync_NewPasswordShorterThanMinimum_Throws()
    {
        var policy = new LengthPasswordPolicy();
        var provider = new TestProvider(minimumLength: 10);
        var context = new PasswordChangeContext("u", "old", "short", new ClientSettings());

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => policy.ValidateAsync(context, provider));

        Assert.Equal(ApiErrorCode.ComplexPassword, ex.ErrorCode);
    }

    [Fact]
    public async Task ValidateAsync_NewPasswordAtOrAboveMinimum_Passes()
    {
        var policy = new LengthPasswordPolicy();
        var provider = new TestProvider(minimumLength: 8);
        var context = new PasswordChangeContext("u", "old", "12345678", new ClientSettings());

        await policy.ValidateAsync(context, provider);
    }

    private sealed class TestProvider : IPasswordChangeProvider, IPasswordLengthRequirement
    {
        private readonly int _minimumLength;
        public TestProvider(int minimumLength) => _minimumLength = minimumLength;

        public Task<int> GetMinimumLengthAsync() => Task.FromResult(_minimumLength);

        public Task<PasswordChangeResult> PerformPasswordChangeAsync(string username, string currentPassword, string newPassword) =>
            Task.FromResult(PasswordChangeResult.Success());
    }
}
