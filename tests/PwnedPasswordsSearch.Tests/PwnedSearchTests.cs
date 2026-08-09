using System;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging.Abstractions;
using PwnedPasswordsSearch;
using Xunit;

namespace PwnedPasswordsSearch.Tests;

public class PwnedSearchTests
{
    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 → prefix "5BAA6", suffix "1E4C9B93F3F0682250B6CF8331B7EE68FD8"
    private const string PasswordSuffix = "1E4C9B93F3F0682250B6CF8331B7EE68FD8";

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
    public async Task IsPwnedPasswordAsync_TransportFailure_ThrowsApiException()
    {
        var factory = new StubHttpClientFactory((_, _) => throw new HttpRequestException("network down"));
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        await Assert.ThrowsAsync<PwnedPasswordsApiException>(() => search.IsPwnedPasswordAsync("password"));
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_RequestUriCorrectness()
    {
        // Assert the handler receives exactly range/XXXXX where the prefix is the first 5 characters of the uppercase SHA-1 of the input.
        // SHA-1("password") is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8, so prefix is 5BAA6 and suffix is 1E4C9B93F3F0682250B6CF8331B7EE68FD8.
        var factory = new StubHttpClientFactory((req, _) =>
        {
            var relativePath = req.RequestUri!.PathAndQuery.TrimStart('/');
            Assert.Equal("range/5BAA6", relativePath);
            return new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = new StringContent($"{PasswordSuffix}:42"),
            };
        });
        var search = new PwnedSearch(factory, NullLogger<PwnedSearch>.Instance);

        await search.IsPwnedPasswordAsync("password");
    }

    [Fact]
    public async Task IsPwnedPasswordAsync_PlaintextNeverLeavesProcess()
    {
        // Assert the request URI and headers contain neither the password nor its full hash.
        const string plaintext = "super_secret_password_123";
        // SHA-1("super_secret_password_123") = C4FC9AA3172C6C0770B7C10985DFB5BB78D69066
        const string fullHash = "C4FC9AA3172C6C0770B7C10985DFB5BB78D69066";
        const string suffix = "AA3172C6C0770B7C10985DFB5BB78D69066";

        var factory = new StubHttpClientFactory((req, _) =>
        {
            var uriString = req.RequestUri!.ToString();

            // Check URI doesn't contain plaintext, full hash, or suffix
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
        // Let's create a mixed case version of the password suffix (e.g., "1e4c9b93f3f0682250b6cf8331b7ee68fd8" with some uppercase: "1E4c9B93f3f0682250b6cf8331b7ee68fd8")
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
