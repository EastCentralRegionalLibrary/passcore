using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace PwnedPasswordsSearch
{
    /// <summary>
    /// Exception thrown when the Pwned Passwords API call fails.
    /// </summary>
    public class PwnedPasswordsApiException : HttpRequestException
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PwnedPasswordsApiException"/> class.
        /// </summary>
        public PwnedPasswordsApiException() : base() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="PwnedPasswordsApiException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The message that describes the error.</param>
        public PwnedPasswordsApiException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="PwnedPasswordsApiException"/> class with a specified error message and inner exception.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="innerException">The inner exception.</param>
        public PwnedPasswordsApiException(string message, Exception? innerException) : base(message, innerException) { }
    }

    /// <summary>
    /// Exception thrown when an unexpected error occurs during Pwned Passwords search.
    /// </summary>
    public class PwnedPasswordsSearchException : Exception
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="PwnedPasswordsSearchException"/> class.
        /// </summary>
        public PwnedPasswordsSearchException() : base() { }

        /// <summary>
        /// Initializes a new instance of the <see cref="PwnedPasswordsSearchException"/> class with a specified error message.
        /// </summary>
        /// <param name="message">The error message.</param>
        public PwnedPasswordsSearchException(string message) : base(message) { }

        /// <summary>
        /// Initializes a new instance of the <see cref="PwnedPasswordsSearchException"/> class with a specified error message and inner exception.
        /// </summary>
        /// <param name="message">The error message.</param>
        /// <param name="innerException">The inner exception.</param>
        public PwnedPasswordsSearchException(string message, Exception? innerException) : base(message, innerException) { }
    }

    /// <summary>
    /// Implementation of the pwned password search service.
    /// </summary>
    public class PwnedSearch : IPwnedPasswordSearch
    {
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<PwnedSearch> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="PwnedSearch"/> class.
        /// </summary>
        /// <param name="httpClientFactory">The http client factory.</param>
        /// <param name="logger">The logger.</param>
        public PwnedSearch(IHttpClientFactory httpClientFactory, ILogger<PwnedSearch> logger)
        {
            _httpClientFactory = httpClientFactory;
            _logger = logger;
        }

        // LoggerMessage delegates for performance optimization
        private static readonly Action<ILogger, string, Exception?> LogPwnedPasswordCheckRequest =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(300, "PwnedPasswordCheckRequest"),
                "Pwned Passwords API request for hash prefix: '{HashPrefix}'.");

        private static readonly Action<ILogger, string, Exception?> LogPwnedPasswordFound =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(301, "PwnedPasswordFound"),
                "Pwned password found for hash suffix: '{HashSuffix}'. Password is compromised.");

        private static readonly Action<ILogger, string, Exception?> LogPwnedPasswordNotFound =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(302, "PwnedPasswordNotFound"),
                "Pwned password not found for hash prefix: '{HashPrefix}'. Password is not publicly known.");

        private static readonly Action<ILogger, string, Exception?> LogPwnedPasswordApiError =
            LoggerMessage.Define<string>(
                LogLevel.Warning,
                new EventId(303, "PwnedPasswordApiError"),
                "Error calling Pwned Passwords API: {ErrorMessage}.");

        private static readonly Action<ILogger, string, Exception?> LogPwnedPasswordUnexpectedError =
            LoggerMessage.Define<string>(
                LogLevel.Error,
                new EventId(304, "PwnedPasswordUnexpectedError"),
                "Unexpected error during Pwned Passwords check: {ErrorMessage}.");

        /// <summary>
        /// Makes an asynchronous call to Pwned Passwords API to check if a password has been compromised.
        /// Throws <see cref="PwnedPasswordsApiException"/> if the API request fails.
        /// Throws <see cref="PwnedPasswordsSearchException"/> for unexpected errors during the password check process.
        /// The calling code is responsible for handling these exceptions.
        /// </summary>
        /// <param name="plaintext">Password to check.</param>
        /// <returns>True if the password is pwned (found in the API), false otherwise.</returns>
        /// <exception cref="PwnedPasswordsApiException">Thrown when the API request fails (e.g., network error, API down).</exception>
        /// <exception cref="PwnedPasswordsSearchException">Thrown for unexpected errors during the password check process.</exception>
        public async Task<bool> IsPwnedPasswordAsync(string plaintext)
        {
            try
            {
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
                byte[] data = SHA1.HashData(Encoding.UTF8.GetBytes(plaintext));
#pragma warning restore CA5350 // Do Not Use Weak Cryptographic Algorithms

                // Format hash as hexadecimal string
                var sBuilder = new StringBuilder();
                foreach (var t in data)
                    sBuilder.Append(t.ToString("x2", System.Globalization.CultureInfo.InvariantCulture));
                var hashResult = sBuilder.ToString().ToUpperInvariant();

                string hashPrefix = hashResult[..5];
                string hashSuffixToCheck = hashResult[5..];

                LogPwnedPasswordCheckRequest(_logger, hashPrefix, null);

                var client = _httpClientFactory.CreateClient("PwnedPasswords");
                HttpResponseMessage? response = null; // Declare response outside using for error context

                try
                {
                    response = await client.GetAsync(new Uri($"range/{hashPrefix}", UriKind.Relative));
                    response.EnsureSuccessStatusCode(); // Throw exception for non-success status codes

                    string responseContent = await response.Content.ReadAsStringAsync();
                    using var reader = new StringReader(responseContent);
                    string? line;
                    while ((line = await reader.ReadLineAsync()) != null)
                    {
                        string[] parts = line.Split(':');
                        if (parts.Length == 2 && string.Equals(parts[0], hashSuffixToCheck, StringComparison.OrdinalIgnoreCase))
                        {
                            LogPwnedPasswordFound(_logger, hashSuffixToCheck, null);
                            return true; // Password is PWNED!
                        }
                    }
                    LogPwnedPasswordNotFound(_logger, hashPrefix, null);
                    return false; // Password not pwned
                }
                catch (HttpRequestException ex) when (response != null)
                {
                    // Capture more context about the API error including status code if available
                    string errorMessage = $"API request failed with status code: {response.StatusCode}. Error message: {ex.Message}";
                    LogPwnedPasswordApiError(_logger, errorMessage, ex);
                    throw new PwnedPasswordsApiException(errorMessage, ex);
                }
                catch (HttpRequestException ex)
                {
                    LogPwnedPasswordApiError(_logger, ex.Message, ex);
                    throw new PwnedPasswordsApiException("Error calling Pwned Passwords API.", ex);
                }
            }
            catch (PwnedPasswordsApiException)
            {
                throw;
            }
            catch (Exception ex)
            {
                LogPwnedPasswordUnexpectedError(_logger, ex.Message, ex);
                throw new PwnedPasswordsSearchException("Unexpected error during pwned password check.", ex);
            }
        }
    }
}
