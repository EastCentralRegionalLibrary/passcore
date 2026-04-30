using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using Xunit;

namespace Unosquare.PassCore.Common.Tests;

public class PasswordChangeProviderBaseTests
{
    private class TestProvider : PasswordChangeProviderBase
    {
        public TestProvider(ILogger logger, IEnumerable<IPasswordPolicy> policies = null) : base(logger, policies) { }

        public override Task<PasswordChangeResult> PerformPasswordChangeAsync(string username, string currentPassword, string newPassword)
        {
            return ChangePasswordAsync(new PasswordChangeContext(username, currentPassword, newPassword, new ClientSettings()));
        }

        protected override Task ChangePasswordCore(PasswordChangeContext context, CancellationToken cancellationToken)
        {
            if (context.Username == "fail") throw new Exception("Operation failed");
            return Task.CompletedTask;
        }

        public Task<PasswordChangeResult> TestChangePasswordAsync(PasswordChangeContext context) => ChangePasswordAsync(context);
    }

    [Fact]
    public async Task ChangePasswordAsync_Success()
    {
        var loggerMock = new Mock<ILogger>();
        var provider = new TestProvider(loggerMock.Object);
        var context = new PasswordChangeContext("user", "old", "new", new ClientSettings());

        var result = await provider.TestChangePasswordAsync(context);

        Assert.True(result.IsSuccessful);
        Assert.Empty(result.Errors);
    }

    [Fact]
    public async Task ChangePasswordAsync_ValidationFailure()
    {
        var loggerMock = new Mock<ILogger>();
        var provider = new TestProvider(loggerMock.Object);
        var context = new PasswordChangeContext("", "old", "new", new ClientSettings());

        var result = await provider.TestChangePasswordAsync(context);

        Assert.False(result.IsSuccessful);
        Assert.Equal(ApiErrorCode.InvalidCredentials, result.Errors.First().ErrorCode);
    }

    [Fact]
    public async Task ChangePasswordAsync_PolicyFailure()
    {
        var loggerMock = new Mock<ILogger>();
        var policyMock = new Mock<IPasswordPolicy>();
        policyMock.Setup(p => p.ValidateAsync(It.IsAny<PasswordChangeContext>(), It.IsAny<IPasswordChangeProvider>()))
            .ThrowsAsync(new PasswordPolicyViolationException("Policy failed", ApiErrorCode.MinimumScore));

        var provider = new TestProvider(loggerMock.Object, new[] { policyMock.Object });
        var context = new PasswordChangeContext("user", "old", "new", new ClientSettings());

        var result = await provider.TestChangePasswordAsync(context);

        Assert.False(result.IsSuccessful);
        Assert.Equal(ApiErrorCode.MinimumScore, result.Errors.First().ErrorCode);
    }

    [Fact]
    public async Task ChangePasswordAsync_CoreFailure()
    {
        var loggerMock = new Mock<ILogger>();
        var provider = new TestProvider(loggerMock.Object);
        var context = new PasswordChangeContext("fail", "old", "new", new ClientSettings());

        var result = await provider.TestChangePasswordAsync(context);

        Assert.False(result.IsSuccessful);
        Assert.Equal(ApiErrorCode.Generic, result.Errors.First().ErrorCode);
        Assert.Equal("Operation failed", result.Errors.First().Message);
    }
}
