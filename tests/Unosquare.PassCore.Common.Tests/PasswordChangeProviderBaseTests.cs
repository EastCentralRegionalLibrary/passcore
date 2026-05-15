using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using Xunit;

namespace Unosquare.PassCore.Common.Tests;

public class PasswordChangeProviderBaseTests
{
    private sealed class TestProvider : PasswordChangeProviderBase
    {
        public bool CoreInvoked { get; private set; }

        public TestProvider(IEnumerable<IPasswordPolicy>? policies = null, ClientSettings? clientSettings = null)
            : base(NullLogger.Instance, clientSettings, policies)
        {
        }

        protected override Task ChangePasswordCore(PasswordChangeContext context, CancellationToken cancellationToken)
        {
            CoreInvoked = true;

            return context.Username switch
            {
                "fail" => throw new InvalidOperationException("Operation failed"),
                "cancel" => throw new OperationCanceledException(),
                "policy" => throw new PasswordPolicyViolationException("policy core", ApiErrorCode.MinimumScore),
                _ => Task.CompletedTask,
            };
        }

        public Task<PasswordChangeResult> TestChangePasswordAsync(PasswordChangeContext context) => ChangePasswordAsync(context);
    }

    [Fact]
    public async Task ChangePasswordAsync_Success()
    {
        var provider = new TestProvider();
        var context = new PasswordChangeContext("user", "old", "new", new ClientSettings());

        var result = await provider.TestChangePasswordAsync(context);

        Assert.True(result.IsSuccessful);
        Assert.Empty(result.Errors);
        Assert.True(provider.CoreInvoked);
    }

    [Theory]
    [InlineData("", "old", "new")]
    [InlineData("user", "", "new")]
    [InlineData("user", "old", "")]
    public async Task ChangePasswordAsync_AnyFieldMissing_FailsAsInvalidCredentialsWithoutInvokingCore(string username, string current, string @new)
    {
        var provider = new TestProvider();
        var context = new PasswordChangeContext(username, current, @new, new ClientSettings());

        var result = await provider.TestChangePasswordAsync(context);

        Assert.False(result.IsSuccessful);
        Assert.Equal(ApiErrorCode.InvalidCredentials, result.Errors.Single().ErrorCode);
        Assert.False(provider.CoreInvoked);
    }

    [Fact]
    public async Task ChangePasswordAsync_PolicyFailure_MapsToErrorCodeAndSkipsCore()
    {
        var policy = new Mock<IPasswordPolicy>();
        policy.Setup(p => p.ValidateAsync(It.IsAny<PasswordChangeContext>(), It.IsAny<IPasswordChangeProvider>()))
            .ThrowsAsync(new PasswordPolicyViolationException("Policy failed", ApiErrorCode.MinimumScore));

        var provider = new TestProvider(new[] { policy.Object });
        var context = new PasswordChangeContext("user", "old", "new", new ClientSettings());

        var result = await provider.TestChangePasswordAsync(context);

        Assert.False(result.IsSuccessful);
        Assert.Equal(ApiErrorCode.MinimumScore, result.Errors.Single().ErrorCode);
        Assert.False(provider.CoreInvoked);
    }

    [Fact]
    public async Task ChangePasswordAsync_PoliciesEvaluatedInOrder_StopOnFirstFailure()
    {
        var calls = new List<string>();
        var first = MakeRecordingPolicy("first", calls);
        var second = MakeRecordingPolicy("second", calls, ApiErrorCode.MinimumDistance);
        var third = MakeRecordingPolicy("third", calls);

        var provider = new TestProvider(new[] { first, second, third });
        var context = new PasswordChangeContext("user", "old", "new", new ClientSettings());

        var result = await provider.TestChangePasswordAsync(context);

        Assert.False(result.IsSuccessful);
        Assert.Equal(new[] { "first", "second" }, calls);
        Assert.Equal(ApiErrorCode.MinimumDistance, result.Errors.Single().ErrorCode);
    }

    [Fact]
    public async Task ChangePasswordAsync_GenericExceptionFromCore_MappedToGeneric()
    {
        var provider = new TestProvider();
        var context = new PasswordChangeContext("fail", "old", "new", new ClientSettings());

        var result = await provider.TestChangePasswordAsync(context);

        Assert.False(result.IsSuccessful);
        Assert.Equal(ApiErrorCode.Generic, result.Errors.Single().ErrorCode);
        Assert.Equal("Operation failed", result.Errors.Single().Message);
    }

    [Fact]
    public async Task ChangePasswordAsync_PasswordChangeExceptionFromCore_MappedViaApiErrorMapper()
    {
        var provider = new TestProvider();
        var context = new PasswordChangeContext("policy", "old", "new", new ClientSettings());

        var result = await provider.TestChangePasswordAsync(context);

        Assert.False(result.IsSuccessful);
        Assert.Equal(ApiErrorCode.MinimumScore, result.Errors.Single().ErrorCode);
    }

    [Fact]
    public async Task ChangePasswordAsync_OperationCanceledFromCore_PropagatesCancellation()
    {
        var provider = new TestProvider();
        var context = new PasswordChangeContext("cancel", "old", "new", new ClientSettings());

        await Assert.ThrowsAsync<OperationCanceledException>(() => provider.TestChangePasswordAsync(context));
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_BuildsContextFromInjectedClientSettings()
    {
        var settings = new ClientSettings { MinimumScore = 7 };
        ClientSettings? captured = null;

        var policy = new Mock<IPasswordPolicy>();
        policy.Setup(p => p.ValidateAsync(It.IsAny<PasswordChangeContext>(), It.IsAny<IPasswordChangeProvider>()))
            .Callback<PasswordChangeContext, IPasswordChangeProvider>((ctx, _) => captured = ctx.ClientSettings)
            .Returns(Task.CompletedTask);

        var provider = new TestProvider(new[] { policy.Object }, clientSettings: settings);

        var result = await provider.PerformPasswordChangeAsync("user", "old", "new");

        Assert.True(result.IsSuccessful);
        Assert.Same(settings, captured);
    }

    private static IPasswordPolicy MakeRecordingPolicy(string name, List<string> calls, ApiErrorCode? failWith = null)
    {
        var mock = new Mock<IPasswordPolicy>();
        var setup = mock.Setup(p => p.ValidateAsync(It.IsAny<PasswordChangeContext>(), It.IsAny<IPasswordChangeProvider>()))
            .Callback(() => calls.Add(name));

        if (failWith is { } code)
            setup.ThrowsAsync(new PasswordPolicyViolationException("fail", code));
        else
            setup.Returns(Task.CompletedTask);

        return mock.Object;
    }
}
