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
