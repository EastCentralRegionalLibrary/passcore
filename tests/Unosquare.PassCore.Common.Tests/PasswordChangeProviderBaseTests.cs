using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
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
        private readonly Func<int?> _minimumLengthLookup;

        public bool CoreInvoked { get; private set; }

        /// <summary>How many times the base actually performed the lookup, which is
        /// what makes the cache observable from outside.</summary>
        public int MinimumLengthLookups { get; private set; }

        public TestProvider(
            IEnumerable<IPasswordPolicy>? policies = null,
            ClientSettings? clientSettings = null,
            Func<int?>? minimumLengthLookup = null,
            ILogger? logger = null)
            : base(logger ?? NullLogger.Instance, clientSettings, policies)
        {
            _minimumLengthLookup = minimumLengthLookup ?? (() => null);
        }

        // Required because the base declares this abstract, which is the point:
        // a provider author has to answer "what is your minimum length" rather
        // than inheriting a silent default. Returning null is a valid answer and
        // takes the shared logged-fallback path.
        protected override Task<int?> ReadMinPwdLength()
        {
            MinimumLengthLookups++;
            return Task.FromResult(_minimumLengthLookup());
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
    public async Task ChangePasswordAsync_GenericExceptionFromCore_MappedToGenericWithoutRawText()
    {
        // Expectation changed deliberately: the catch-all used to serialize the
        // raw exception message ("Operation failed"), which the UI renders
        // verbatim for the Generic code. It now returns a clean surface message
        // carrying only a correlation reference; the detail stays in logs.
        var provider = new TestProvider();
        var context = new PasswordChangeContext("fail", "old", "new", new ClientSettings());

        var result = await provider.TestChangePasswordAsync(context);

        Assert.False(result.IsSuccessful);
        var error = result.Errors.Single();
        Assert.Equal(ApiErrorCode.Generic, error.ErrorCode);
        Assert.NotNull(error.Message);
        Assert.StartsWith("An unexpected error occurred", error.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("Operation failed", error.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_GeneratesCorrelationIdAndEmbedsItInGenericFailures()
    {
        string? observedCorrelationId = null;

        var policy = new Mock<IPasswordPolicy>();
        policy.Setup(p => p.ValidateAsync(It.IsAny<PasswordChangeContext>(), It.IsAny<IPasswordChangeProvider>()))
            .Callback<PasswordChangeContext, IPasswordChangeProvider>((ctx, _) => observedCorrelationId = ctx.CorrelationId)
            .Returns(Task.CompletedTask);

        var provider = new TestProvider(new[] { policy.Object });

        var result = await provider.PerformPasswordChangeAsync("fail", "old", "new");

        Assert.False(string.IsNullOrWhiteSpace(observedCorrelationId));
        Assert.False(result.IsSuccessful);
        var error = result.Errors.Single();
        Assert.Equal(ApiErrorCode.Generic, error.ErrorCode);
        Assert.NotNull(error.Message);
        Assert.Contains(observedCorrelationId!, error.Message, StringComparison.Ordinal);
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

    /// <summary>
    /// A directory-sourced value is returned as read, and reading it once serves
    /// every later request within the TTL. This runs on every POST before the
    /// caller has proved anything, so re-reading per request would hand an
    /// unauthenticated caller a cheap way to generate directory load.
    /// </summary>
    [Fact]
    public async Task TheMinimumLengthIsReadFromTheProviderAndThenCached()
    {
        var provider = new TestProvider(minimumLengthLookup: () => 14);

        for (var i = 0; i < 5; i++)
            Assert.Equal(14, await provider.GetMinimumLengthAsync());

        Assert.Equal(1, provider.MinimumLengthLookups);
    }

    /// <summary>
    /// The cache belongs to the provider instance, not to the type. Two providers
    /// could be pointed at two directories with different policies, and a shared
    /// cache would advertise one directory's minimum for the other's users.
    /// </summary>
    [Fact]
    public async Task TwoProviderInstancesDoNotShareACachedMinimumLength()
    {
        var first = new TestProvider(minimumLengthLookup: () => 14);
        var second = new TestProvider(minimumLengthLookup: () => 20);

        Assert.Equal(14, await first.GetMinimumLengthAsync());
        Assert.Equal(20, await second.GetMinimumLengthAsync());

        // And each still performed its own read, rather than one answering for both.
        Assert.Equal(1, first.MinimumLengthLookups);
        Assert.Equal(1, second.MinimumLengthLookups);
    }

    /// <summary>
    /// A provider with no domain policy to read returns null, and that is a handled
    /// answer rather than a failure: the shared resolver logs it and advertises the
    /// fallback. This is why the base can implement
    /// <see cref="IPasswordLengthRequirement"/> for every provider instead of each
    /// one opting in.
    /// </summary>
    [Fact]
    public async Task ALookupReturningNullFallsBackVisiblyRatherThanFailing()
    {
        var logger = new CapturingLogger();
        var provider = new TestProvider(minimumLengthLookup: () => null, logger: logger);

        Assert.Equal(DomainPasswordPolicy.DefaultMinimumLength, await provider.GetMinimumLengthAsync());

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains("minPwdLength", entry.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A lookup that throws — an unreachable domain controller, a service account
    /// that cannot read the policy — must not propagate out of a password change.
    /// It becomes the same logged fallback, with the exception kept for the
    /// operator.
    /// </summary>
    [Fact]
    public async Task ALookupThatThrowsFallsBackVisiblyRatherThanPropagating()
    {
        var logger = new CapturingLogger();
        var boom = new InvalidOperationException("DC unreachable");
        var provider = new TestProvider(minimumLengthLookup: () => throw boom, logger: logger);

        Assert.Equal(DomainPasswordPolicy.DefaultMinimumLength, await provider.GetMinimumLengthAsync());

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Same(boom, entry.Exception);
    }

    /// <summary>
    /// The fallback is deliberately not cached, so a failing lookup keeps
    /// re-attempting and keeps logging. Caching it would suppress the
    /// operator-actionable warning for the whole TTL — which is exactly the signal
    /// that something is wrong.
    /// </summary>
    [Fact]
    public async Task AFailingLookupIsRetriedRatherThanCached()
    {
        var provider = new TestProvider(minimumLengthLookup: () => null);

        for (var i = 0; i < 3; i++)
            await provider.GetMinimumLengthAsync();

        Assert.Equal(3, provider.MinimumLengthLookups);
    }

    private sealed class CapturingLogger : ILogger
    {
        public List<(LogLevel Level, string Message, Exception? Exception)> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) =>
            Entries.Add((logLevel, formatter(state, exception), exception));
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
