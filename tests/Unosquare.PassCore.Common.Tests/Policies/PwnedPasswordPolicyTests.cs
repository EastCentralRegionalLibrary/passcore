using System;
using System.Threading.Tasks;
using PwnedPasswordsSearch;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using Unosquare.PassCore.Common.Policies;
using Unosquare.PassCore.Testing;
using Xunit;

namespace Unosquare.PassCore.Common.Tests.Policies;

public class PwnedPasswordPolicyTests
{
    [Fact]
    public async Task ValidateAsync_PwnedCheckDisabled_DoesNotInvokeSearch()
    {
        var search = new ThrowingSearch();
        var policy = new PwnedPasswordPolicy(search);
        var settings = new ClientSettings { EnablePwnedPasswordCheck = false };
        var context = new PasswordChangeContext("u", "old", "any", settings);

        await policy.ValidateAsync(context, provider: null!);

        Assert.False(search.WasCalled);
    }

    [Fact]
    public async Task ValidateAsync_CleanPassword_Passes()
    {
        var search = new MockPwnedSearch();
        var policy = new PwnedPasswordPolicy(search);
        var settings = new ClientSettings { EnablePwnedPasswordCheck = true };
        var context = new PasswordChangeContext("u", "old", "unique-passphrase-92!", settings);

        await policy.ValidateAsync(context, provider: null!);
    }

    [Fact]
    public async Task ValidateAsync_KnownPwnedPassword_Throws()
    {
        var search = new MockPwnedSearch();
        search.AddPwnedPassword("hunter2");
        var policy = new PwnedPasswordPolicy(search);
        var settings = new ClientSettings { EnablePwnedPasswordCheck = true };
        var context = new PasswordChangeContext("u", "old", "hunter2", settings);

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => policy.ValidateAsync(context, provider: null!));

        Assert.Equal(ApiErrorCode.PwnedPassword, ex.ErrorCode);
    }

    [Fact]
    public async Task ValidateAsync_ApiFailureBubblesAsGenericPolicyViolation()
    {
        var search = new FaultySearch(new PwnedPasswordsApiException("nope", null));
        var policy = new PwnedPasswordPolicy(search);
        var settings = new ClientSettings { EnablePwnedPasswordCheck = true };
        var context = new PasswordChangeContext("u", "old", "any", settings);

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => policy.ValidateAsync(context, provider: null!));

        Assert.Equal(ApiErrorCode.Generic, ex.ErrorCode);
    }

    [Theory]
    [InlineData(typeof(PwnedPasswordsApiException))]
    [InlineData(typeof(PwnedPasswordsSearchException))]
    public async Task ValidateAsync_ApiFailure_NeverLeaksClientExceptionText(Type exceptionType)
    {
        // The Generic code renders its message verbatim in the UI, so the HIBP
        // client's internal detail must never appear in it — only a clean
        // message with the correlation reference.
        var raw = (Exception)Activator.CreateInstance(
            exceptionType, "HIBP internals: socket timed out at 10.0.0.5:443", null)!;
        var search = new FaultySearch(raw);
        var policy = new PwnedPasswordPolicy(search);
        var settings = new ClientSettings { EnablePwnedPasswordCheck = true };
        var context = new PasswordChangeContext("u", "old", "any", settings, correlationId: "abc12345");

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => policy.ValidateAsync(context, provider: null!));

        Assert.Equal(ApiErrorCode.Generic, ex.ErrorCode);
        Assert.DoesNotContain("HIBP internals", ex.Message, StringComparison.Ordinal);
        Assert.DoesNotContain("10.0.0.5", ex.Message, StringComparison.Ordinal);
        Assert.Contains("abc12345", ex.Message, StringComparison.Ordinal);
        Assert.Same(raw, ex.InnerException); // detail preserved for the base class's logging
    }

    private sealed class ThrowingSearch : IPwnedPasswordSearch
    {
        public bool WasCalled { get; private set; }
        public Task<bool> IsPwnedPasswordAsync(string plaintext)
        {
            WasCalled = true;
            throw new InvalidOperationException("Should not be called");
        }
    }

    private sealed class FaultySearch : IPwnedPasswordSearch
    {
        private readonly Exception _toThrow;
        public FaultySearch(Exception toThrow) => _toThrow = toThrow;
        public Task<bool> IsPwnedPasswordAsync(string plaintext) => throw _toThrow;
    }
}
