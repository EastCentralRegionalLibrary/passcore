using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using PwnedPasswordsSearch;
using Xunit;

namespace PwnedPasswordsSearch.Tests;

public class PwnedSearchTests
{
    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 → prefix "5BAA6", suffix "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    private const string PasswordSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

    // SHA-1("LoggingRegressionTestPassword!") = 6C1C9147BD094CD0F22A352E17F5B64FC375330A
    private const string RegressionPassword = "LoggingRegressionTestPassword!";
    private const string RegressionFullHash = "6C1C9147BD094CD0F22A352E17F5B64FC375330A";
    private const string RegressionPrefix = "6C1C9";
    private const string RegressionSuffix = "147BD094CD0F22A352E17F5B64FC375330A";

    [Fact]
    public async Task IsPwnedPasswordAsync_HashSuffixPresent_ReturnsTrue()
    {
        var factory = new StubHttpClientFactory((req, _) =>
        {
            Assert.EndsWith("range/5BAA6", req.RequestUri!.ToString(), StringComparison.OrdinalIgnoreCase);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"{PasswordSuffix}:42\r\nAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1"),
            };
        });

        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        Assert.True(await search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_HashSuffixAbsent_ReturnsFalse()
    {
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2"),
        });
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        Assert.False(await search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_NonSuccessResponse_ThrowsApiException()
    {
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        await Assert.ThrowsAsync<PwnedPasswordsApiException>(() => search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_DoesNotSendFullHashOrPlaintext()
    {
        const string plaintext = "SecretPassword123!";
        // SHA1("SecretPassword123!") = 65BF280069AF45EB4489F4BD4F701E7469523234
        const string fullHash = "65BF280069AF45EB4489F4BD4F701E7469523234";
        const string prefix = "65BF2";
        const string suffix = "80069AF45EB4489F4BD4F701E7469523234";

        var factory = new StubHttpClientFactory((req, _) =>
        {
            var uriString = req.RequestUri!.ToString();
            Assert.EndsWith($"range/{prefix}", uriString, StringComparison.OrdinalIgnoreCase);

            // Ensure the URL does NOT contain plaintext, full hash, or suffix
            Assert.DoesNotContain(plaintext, uriString, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(fullHash, uriString, StringComparison.OrdinalIgnoreCase);
            Assert.DoesNotContain(suffix, uriString, StringComparison.OrdinalIgnoreCase);

            // Check headers
            foreach (var header in req.Headers)
            {
                Assert.DoesNotContain(plaintext, header.Key, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(fullHash, header.Key, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(suffix, header.Key, StringComparison.OrdinalIgnoreCase);
                foreach (var val in header.Value)
                {
                    Assert.DoesNotContain(plaintext, val, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain(fullHash, val, StringComparison.OrdinalIgnoreCase);
                    Assert.DoesNotContain(suffix, val, StringComparison.OrdinalIgnoreCase);
                }
            }

            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"{suffix}:1"),
            };
        });

        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);
        Assert.True(await search.IsPwnedPasswordAsync(plaintext));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_SuffixOnSubsequentLine_ReturnsTrue()
    {
        // Suffix found on a line that is not the first line of a multi-line response.
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\n{PasswordSuffix}:999\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2"),
        });
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        Assert.True(await search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_SuffixMatchWithNoColon_DoesNotMatch()
    {
        // A line whose suffix matches but which has no colon -- must NOT count as a match.
        // The first line has no colon, but the second line has a valid match.
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{PasswordSuffix}\r\n{PasswordSuffix}:42"),
        });
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        Assert.True(await search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_SuffixMatchWithNoColonOnly_ReturnsFalse()
    {
        // Suffix matches but no colon present at all.
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{PasswordSuffix}"),
        });
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        Assert.False(await search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_SuffixMatchWithMultipleColons_DoesNotMatch()
    {
        // A line whose suffix matches but has more than one colon -- must NOT count as a match.
        // The first line has multiple colons, but the second line has a valid match.
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{PasswordSuffix}:42:extra\r\n{PasswordSuffix}:42"),
        });
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        Assert.True(await search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_SuffixMatchWithMultipleColonsOnly_ReturnsFalse()
    {
        // Suffix matches but multiple colons present.
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{PasswordSuffix}:42:extra"),
        });
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        Assert.False(await search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_SuffixDiffersInCase_ReturnsTrue()
    {
        // Assert that the comparison is deliberately case-insensitive, because a case mismatch
        // would otherwise report a breached password as safe.
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{PasswordSuffix.ToLowerInvariant()}:42"),
        });
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        Assert.True(await search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_SuffixMixedCase_ReturnsTrue()
    {
        // Assert that a mixed-case suffix in the response is also correctly matched.
        const string mixedCaseSuffix = "1E4c9B93f3f0682250b6cf8331b7ee68fd8";
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent($"{mixedCaseSuffix}:42"),
        });
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        Assert.True(await search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_EmptyStringPassword_DoesNotThrow()
    {
        // Empty-string password (hashes fine, should complete without throwing).
        // SHA-1 of empty string is DA39A3EE5E6B4B0D3255BFEF95601890AFD80709
        var factory = new StubHttpClientFactory((req, _) =>
        {
            Assert.EndsWith("range/DA39A", req.RequestUri!.ToString(), StringComparison.OrdinalIgnoreCase);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent("3EE5E6B4B0D3255BFEF95601890AFD80709:1"),
            };
        });
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        Assert.True(await search.IsPwnedPasswordAsync(""));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_EmptyResponseBody_ReturnsFalse()
    {
        // An empty response body -- returns false.
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(""),
        });
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        Assert.False(await search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_WhitespaceOnlyResponseBody_ReturnsFalse()
    {
        // A response body of only whitespace or blank lines -- returns false.
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("   \r\n\r\n   "),
        });
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        Assert.False(await search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_UnexpectedException_ThrowsPwnedPasswordsSearchException()
    {
        // A non-HttpRequestException failure from the handler (throw e.g. InvalidOperationException)
        // surfaces as PwnedPasswordsSearchException, not PwnedPasswordsApiException.
        var factory = new StubHttpClientFactory((_, _) => throw new InvalidOperationException("unexpected failure"));
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        var ex = await Assert.ThrowsAsync<PwnedPasswordsSearchException>(() => search.IsPwnedPasswordAsync("password"));
        Assert.IsType<InvalidOperationException>(ex.InnerException);
        Assert.Equal("unexpected failure", ex.InnerException.Message);
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_ApiException_IsRethrownUnchanged()
    {
        // PwnedPasswordsApiException is rethrown unchanged rather than being re-wrapped
        // as PwnedPasswordsSearchException by the outer catch.
        var expectedInner = new PwnedPasswordsApiException("simulated original api failure");
        var factory = new StubHttpClientFactory((_, _) => throw expectedInner);
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        var ex = await Assert.ThrowsAsync<PwnedPasswordsApiException>(() => search.IsPwnedPasswordAsync("password"));
        Assert.IsNotType<PwnedPasswordsSearchException>(ex);
    }

    // -------------------------------------------------------------------------
    // Logging regression tests
    // -------------------------------------------------------------------------

    [Fact]
    public async Task IsPwnedPasswordAsync_NonCompromisedPassword_LogsDoNotExposeSensitiveData()
    {
        var logger = new CapturingLogger<PwnedSearch>();
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:1\r\nBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB:2"),
        });

        var search = new PwnedSearch(factory, logger);
        var result = await search.IsPwnedPasswordAsync(RegressionPassword);

        Assert.False(result);
        AssertNoPasswordDerivedDataInLogs(logger, RegressionPassword, RegressionFullHash, RegressionPrefix, RegressionSuffix);

        Assert.Contains(logger.Entries, e => e.EventId.Id == 300);
        Assert.Contains(logger.Entries, e => e.EventId.Id == 302);
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_CompromisedPassword_LogsDoNotExposeSensitiveData()
    {
        var logger = new CapturingLogger<PwnedSearch>();
        var rawResponseLine = $"{RegressionSuffix}:42";
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.OK)
        {
            Content = new StringContent(rawResponseLine),
        });

        var search = new PwnedSearch(factory, logger);
        var result = await search.IsPwnedPasswordAsync(RegressionPassword);

        Assert.True(result);
        AssertNoPasswordDerivedDataInLogs(logger, RegressionPassword, RegressionFullHash, RegressionPrefix, RegressionSuffix, rawResponseLine);

        Assert.Contains(logger.Entries, e => e.EventId.Id == 300);
        Assert.Contains(logger.Entries, e => e.EventId.Id == 301);
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_NonSuccessStatusCode_LogsDoNotExposeSensitiveData()
    {
        var logger = new CapturingLogger<PwnedSearch>();
        var factory = new StubHttpClientFactory((_, _) => new HttpResponseMessage(HttpStatusCode.InternalServerError));

        var search = new PwnedSearch(factory, logger);
        await Assert.ThrowsAsync<PwnedPasswordsApiException>(() => search.IsPwnedPasswordAsync(RegressionPassword));

        AssertNoPasswordDerivedDataInLogs(logger, RegressionPassword, RegressionFullHash, RegressionPrefix, RegressionSuffix);
        Assert.Contains(logger.Entries, e => e.EventId.Id == 303);
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_NetworkException_LogsDoNotExposeSensitiveData()
    {
        var logger = new CapturingLogger<PwnedSearch>();
        var factory = new StubHttpClientFactory((_, _) =>
            throw new HttpRequestException($"Connection failed for https://api.pwnedpasswords.com/range/{RegressionPrefix}"));

        var search = new PwnedSearch(factory, logger);
        await Assert.ThrowsAsync<PwnedPasswordsApiException>(() => search.IsPwnedPasswordAsync(RegressionPassword));

        AssertNoPasswordDerivedDataInLogs(logger, RegressionPassword, RegressionFullHash, RegressionPrefix, RegressionSuffix);
        Assert.Contains(logger.Entries, e => e.EventId.Id == 303);
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_UnexpectedException_LogsDoNotExposeSensitiveData()
    {
        var logger = new CapturingLogger<PwnedSearch>();
        var factory = new StubHttpClientFactory((_, _) =>
            throw new InvalidOperationException($"Unexpected error calling https://api.pwnedpasswords.com/range/{RegressionPrefix}"));

        var search = new PwnedSearch(factory, logger);
        await Assert.ThrowsAsync<PwnedPasswordsSearchException>(() => search.IsPwnedPasswordAsync(RegressionPassword));

        AssertNoPasswordDerivedDataInLogs(logger, RegressionPassword, RegressionFullHash, RegressionPrefix, RegressionSuffix);
        Assert.Contains(logger.Entries, e => e.EventId.Id == 304);
    }

    private static void AssertNoPasswordDerivedDataInLogs(
        CapturingLogger<PwnedSearch> logger,
        string plaintext,
        string fullHash,
        string prefix,
        string suffix,
        string? rawResponseLine = null)
    {
        Assert.NotEmpty(logger.Entries);

        foreach (var entry in logger.Entries)
        {
            var stringsToCheck = new List<string>
            {
                entry.StateString,
                entry.FormattedMessage,
            };

            if (entry.Exception != null)
            {
                stringsToCheck.Add(entry.Exception.Message);
                stringsToCheck.Add(entry.Exception.ToString());
            }

            foreach (var str in stringsToCheck)
            {
                Assert.DoesNotContain(plaintext, str, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(fullHash, str, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(prefix, str, StringComparison.OrdinalIgnoreCase);
                Assert.DoesNotContain(suffix, str, StringComparison.OrdinalIgnoreCase);

                if (!string.IsNullOrEmpty(rawResponseLine))
                {
                    Assert.DoesNotContain(rawResponseLine, str, StringComparison.OrdinalIgnoreCase);
                }
            }
        }
    }

    private sealed class CapturingLogger<T> : ILogger<T>
    {
        public List<LogEntry> Entries { get; } = new();

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(LogLevel logLevel, EventId eventId, TState state, Exception? exception, Func<TState, Exception?, string> formatter)
        {
            var message = formatter(state, exception);
            Entries.Add(new LogEntry(logLevel, eventId, state?.ToString() ?? string.Empty, message, exception));
        }
    }

    private sealed record LogEntry(LogLevel LogLevel, EventId EventId, string StateString, string FormattedMessage, Exception? Exception);

    private sealed class StubHttpClientFactory : IHttpClientFactory
    {
        private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _handler;

        public StubHttpClientFactory(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> handler) =>
            _handler = handler;

        public HttpClient CreateClient(string name) =>
            new(new StubHandler(_handler))
            {
                BaseAddress = new Uri("https://api.pwnedpasswords.com/"),
            };

        private sealed class StubHandler : HttpMessageHandler
        {
            private readonly Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> _handler;
            public StubHandler(Func<HttpRequestMessage, CancellationToken, HttpResponseMessage> handler) => _handler = handler;
            protected override Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken) =>
                Task.FromResult(_handler(request, cancellationToken));
        }
    }
}
