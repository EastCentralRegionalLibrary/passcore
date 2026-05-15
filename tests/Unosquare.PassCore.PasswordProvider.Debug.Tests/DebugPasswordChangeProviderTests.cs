using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Models;
using Xunit;

namespace Unosquare.PassCore.PasswordProvider.Debug.Tests;

public class DebugPasswordChangeProviderTests
{
    private static DebugPasswordChangeProvider CreateProvider(
        DebugProviderOptions? options = null,
        ClientSettings? clientSettings = null,
        IEnumerable<IPasswordPolicy>? policies = null) =>
        new(
            Options.Create(options ?? new DebugProviderOptions()),
            Options.Create(clientSettings ?? new ClientSettings()),
            NullLogger<DebugPasswordChangeProvider>.Instance,
            policies ?? Array.Empty<IPasswordPolicy>());

    [Fact]
    public async Task PerformPasswordChangeAsync_NoForcedError_Succeeds()
    {
        var result = await CreateProvider().PerformPasswordChangeAsync("someuser", "old", "newPass!");

        Assert.True(result.IsSuccessful);
        Assert.Empty(result.Errors);
    }

    [Theory]
    [InlineData("error", ApiErrorCode.Generic)]
    [InlineData("changeNotPermitted", ApiErrorCode.ChangeNotPermitted)]
    [InlineData("fieldMismatch", ApiErrorCode.FieldMismatch)]
    [InlineData("fieldRequired", ApiErrorCode.FieldRequired)]
    [InlineData("invalidCaptcha", ApiErrorCode.InvalidCaptcha)]
    [InlineData("invalidCredentials", ApiErrorCode.InvalidCredentials)]
    [InlineData("invalidDomain", ApiErrorCode.InvalidDomain)]
    [InlineData("userNotFound", ApiErrorCode.UserNotFound)]
    [InlineData("ldapProblem", ApiErrorCode.LdapProblem)]
    [InlineData("pwnedPassword", ApiErrorCode.PwnedPassword)]
    [InlineData("complexPassword", ApiErrorCode.ComplexPassword)]
    [InlineData("minimumScore", ApiErrorCode.MinimumScore)]
    [InlineData("minimumDistance", ApiErrorCode.MinimumDistance)]
    public async Task PerformPasswordChangeAsync_LegacyForcedErrorByUsername_ProducesExpectedCode(string username, ApiErrorCode expected)
    {
        var result = await CreateProvider().PerformPasswordChangeAsync(username, "old", "newPass!");

        Assert.False(result.IsSuccessful);
        Assert.Equal(expected, result.Errors.Single().ErrorCode);
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_LegacyForcedErrorIsCaseInsensitive()
    {
        var result = await CreateProvider().PerformPasswordChangeAsync("INVALIDCREDENTIALS", "old", "newPass!");

        Assert.False(result.IsSuccessful);
        Assert.Equal(ApiErrorCode.InvalidCredentials, result.Errors.Single().ErrorCode);
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_ConfiguredForcedError_TakesPrecedenceOverLegacy()
    {
        var options = new DebugProviderOptions();
        options.ForcedErrors["error"] = ApiErrorCode.PwnedPassword;

        var result = await CreateProvider(options).PerformPasswordChangeAsync("error@test.com", "old", "newPass!");

        Assert.False(result.IsSuccessful);
        Assert.Equal(ApiErrorCode.PwnedPassword, result.Errors.Single().ErrorCode);
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_ConfiguredForcedError_StripsDomainBeforeMatching()
    {
        var options = new DebugProviderOptions();
        options.ForcedErrors["specialuser"] = ApiErrorCode.ChangeNotPermitted;

        var result = await CreateProvider(options).PerformPasswordChangeAsync("specialuser@domain.com", "old", "newPass!");

        Assert.False(result.IsSuccessful);
        Assert.Equal(ApiErrorCode.ChangeNotPermitted, result.Errors.Single().ErrorCode);
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_DefaultErrorCode_AppliesWhenNothingMatches()
    {
        var options = new DebugProviderOptions { DefaultErrorCode = ApiErrorCode.InvalidCredentials };

        var result = await CreateProvider(options).PerformPasswordChangeAsync("anyuser", "old", "newPass!");

        Assert.False(result.IsSuccessful);
        Assert.Equal(ApiErrorCode.InvalidCredentials, result.Errors.Single().ErrorCode);
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_SimulatedLatency_IsRespected()
    {
        var options = new DebugProviderOptions { SimulateLatencyMs = 75 };
        var provider = CreateProvider(options);

        var stopwatch = Stopwatch.StartNew();
        await provider.PerformPasswordChangeAsync("user", "old", "newPass!");
        stopwatch.Stop();

        Assert.True(stopwatch.ElapsedMilliseconds >= 60,
            $"Expected ~75ms latency, observed {stopwatch.ElapsedMilliseconds}ms");
    }

    [Fact]
    public void Constructor_NullOptions_Throws()
    {
        Assert.Throws<ArgumentNullException>(() => new DebugPasswordChangeProvider(
            null!,
            Options.Create(new ClientSettings()),
            NullLogger<DebugPasswordChangeProvider>.Instance,
            Array.Empty<IPasswordPolicy>()));
    }
}
