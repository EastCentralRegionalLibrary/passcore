using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Moq;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.PasswordProvider.Debug;
using Unosquare.PassCore.Testing;
using Xunit;

namespace Unosquare.PassCore.PasswordProvider.Debug.Tests;

#if DEBUG
public class DebugPasswordChangeProviderTests
{
    private readonly Mock<ILogger<DebugPasswordChangeProvider>> _loggerMock;
    private readonly MockPwnedSearch _pwnedSearch;
    private readonly DebugProviderOptions _options;

    public DebugPasswordChangeProviderTests()
    {
        _loggerMock = new Mock<ILogger<DebugPasswordChangeProvider>>();
        _pwnedSearch = new MockPwnedSearch();
        _options = new DebugProviderOptions();
    }

    private DebugPasswordChangeProvider CreateProvider()
    {
        var optionsMock = new Mock<IOptions<DebugProviderOptions>>();
        optionsMock.Setup(o => o.Value).Returns(_options);
        return new DebugPasswordChangeProvider(optionsMock.Object, _loggerMock.Object, Array.Empty<IPasswordPolicy>());
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_SuccessPath()
    {
        // Arrange
        var provider = CreateProvider();

        // Act
        var result = await provider.PerformPasswordChangeAsync("someuser", "old", "new");

        // Assert
        Assert.Null(result);
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_ForcedErrorByUsername_Legacy()
    {
        // Arrange
        var provider = CreateProvider();

        // Act
        var result = await provider.PerformPasswordChangeAsync("error", "old", "new");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ApiErrorCode.Generic, result.ErrorCode);
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_ForcedErrorByOptions()
    {
        // Arrange
        _options.ForcedErrors.Add("specialuser", ApiErrorCode.ChangeNotPermitted);
        var provider = CreateProvider();

        // Act
        var result = await provider.PerformPasswordChangeAsync("specialuser@domain.com", "old", "new");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ApiErrorCode.ChangeNotPermitted, result.ErrorCode);
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_SimulateLatency()
    {
        // Arrange
        _options.SimulateLatencyMs = 100;
        var provider = CreateProvider();
        var startTime = DateTime.UtcNow;

        // Act
        await provider.PerformPasswordChangeAsync("user", "old", "new");

        // Assert
        var duration = DateTime.UtcNow - startTime;
        Assert.True(duration.TotalMilliseconds >= 100);
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_HonorCancellationToken()
    {
        // Arrange
        _options.SimulateLatencyMs = 1000;
        var provider = CreateProvider();
        using var cts = new CancellationTokenSource();

        // Act
        var task = provider.PerformPasswordChangeAsync("user", "old", "new", cts.Token);
        cts.Cancel();

        // Assert
        await Assert.ThrowsAsync<TaskCanceledException>(() => task);
    }

    [Fact]
    public async Task PerformPasswordChangeAsync_DefaultErrorCode()
    {
        // Arrange
        _options.DefaultErrorCode = ApiErrorCode.InvalidCredentials;
        var provider = CreateProvider();

        // Act
        var result = await provider.PerformPasswordChangeAsync("anyuser", "old", "new");

        // Assert
        Assert.NotNull(result);
        Assert.Equal(ApiErrorCode.InvalidCredentials, result.ErrorCode);
    }
}
#endif
