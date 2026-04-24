using System;
using System.Collections.Generic;
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

        protected override Task ChangePasswordCore(PasswordChangeContext context, CancellationToken cancellationToken)
        {
            if (context.Username == "fail") throw new Exception("Operation failed");
            return Task.CompletedTask;
        }
    }

    [Fact]
    public async Task ChangePasswordAsync_Success()
    {
        var loggerMock = new Mock<ILogger>();
        var provider = new TestProvider(loggerMock.Object);
        var context = new PasswordChangeContext("user", "old", "new", new ClientSettings());

        var result = await provider.ChangePasswordAsync(context);

        Assert.True(result.IsSuccess);
        Assert.Null(result.Error);
    }

    [Fact]
    public async Task ChangePasswordAsync_ValidationFailure()
    {
        var loggerMock = new Mock<ILogger>();
        var provider = new TestProvider(loggerMock.Object);
        var context = new PasswordChangeContext("", "old", "new", new ClientSettings());

        var result = await provider.ChangePasswordAsync(context);

        Assert.False(result.IsSuccess);
        Assert.Equal(ApiErrorCode.InvalidCredentials, result.Error.ErrorCode);
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

        var result = await provider.ChangePasswordAsync(context);

        Assert.False(result.IsSuccess);
        Assert.Equal(ApiErrorCode.MinimumScore, result.Error.ErrorCode);
    }

    [Fact]
    public async Task ChangePasswordAsync_CoreFailure()
    {
        var loggerMock = new Mock<ILogger>();
        var provider = new TestProvider(loggerMock.Object);
        var context = new PasswordChangeContext("fail", "old", "new", new ClientSettings());

        var result = await provider.ChangePasswordAsync(context);

        Assert.False(result.IsSuccess);
        Assert.Equal(ApiErrorCode.Generic, result.Error.ErrorCode);
        Assert.Equal("Operation failed", result.Error.Message);
    }
}
