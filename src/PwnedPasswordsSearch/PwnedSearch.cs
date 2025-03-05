using System;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace PwnedPasswordsSearch
{
    // Custom exception types for better error handling
    public class PwnedPasswordsApiException : HttpRequestException
    {
        public PwnedPasswordsApiException(string message, Exception? innerException) : base(message, innerException) { }
    }

    public class PwnedPasswordsSearchException : Exception
    {
        public PwnedPasswordsSearchException(string message, Exception? innerException) : base(message, innerException) { }
    }

    public static class PwnedSearch
    {
        // LoggerMessage delegates for performance optimization
        private static readonly Action<ILogger?, string, Exception?> LogPwnedPasswordCheckRequest =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(300, "PwnedPasswordCheckRequest"),
                "Pwned Passwords API request for hash prefix: '{HashPrefix}'.");

        private static readonly Action<ILogger?, string, Exception?> LogPwnedPasswordFound =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(301, "PwnedPasswordFound"),
                "Pwned password found for hash suffix: '{HashSuffix}'. Password is compromised.");

        private static readonly Action<ILogger?, string, Exception?> LogPwnedPasswordNotFound =
            LoggerMessage.Define<string>(
                LogLevel.Debug,
                new EventId(302, "PwnedPasswordNotFound"),
                "Pwned password not found for hash prefix: '{HashPrefix}'. Password is not publicly known.");

        private static readonly Action<ILogger?, string, Exception?> LogPwnedPasswordApiError =
            LoggerMessage.Define<string>(
                LogLevel.Warning,
                new EventId(303, "PwnedPasswordApiError"),
                "Error calling Pwned Passwords API: {ErrorMessage}.");

        private static readonly Action<ILogger?, string, Exception?> LogPwnedPasswordUnexpectedError =
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
        /// <param name="logger">Optional logger for logging events.</param>
        /// <returns>True if the password is pwned (found in the API), false otherwise.</returns>
        /// <exception cref="PwnedPasswordsApiException">Thrown when the API request fails (e.g., network error, API down).</exception>
        /// <exception cref="PwnedPasswordsSearchException">Thrown for unexpected errors during the password check process.</exception>
        public static async Task<bool> IsPwnedPasswordAsync(string plaintext, ILogger? logger = null)
        {
            try
            {
#pragma warning disable CA5350 // Do Not Use Weak Cryptographic Algorithms
                using var sha = SHA1.Create();
#pragma warning restore CA5350 // Do Not Use Weak Cryptographic Algorithms
                byte[] data = sha.ComputeHash(Encoding.UTF8.GetBytes(plaintext));

                // Format hash as hexadecimal string
                var sBuilder = new StringBuilder();
                foreach (var t in data)
                    sBuilder.Append(t.ToString("x2"));
                var hashResult = sBuilder.ToString().ToUpperInvariant();

                string hashPrefix = hashResult[..5];
                string hashSuffixToCheck = hashResult[5..];

                LogPwnedPasswordCheckRequest(logger, hashPrefix, null);

                var uriString = $"https://api.pwnedpasswords.com/range/{hashPrefix}";

                using var client = new HttpClient();
                HttpResponseMessage response = null; // Declare response outside using for error context

                try
                {
                    response = await client.GetAsync(new Uri(uriString));
                    response.EnsureSuccessStatusCode(); // Throw exception for non-success status codes

                    string responseContent = await response.Content.ReadAsStringAsync();
                    using var reader = new StringReader(responseContent);
                    string? line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        string[] parts = line.Split(':');
                        if (parts.Length == 2 && parts[0] == hashSuffixToCheck)
                        {
                            LogPwnedPasswordFound(logger, hashSuffixToCheck, null);
                            return true; // Password is PWNED!
                        }
                    }
                    LogPwnedPasswordNotFound(logger, hashPrefix, null);
                    return false; // Password not pwned
                }
                catch (HttpRequestException ex) when (response != null)
                {
                    // Capture more context about the API error including status code if available
                    string errorMessage = $"API request failed with status code: {response.StatusCode}. Error message: {ex.Message}";
                    LogPwnedPasswordApiError(logger, errorMessage, ex);
                    throw new PwnedPasswordsApiException(errorMessage, ex);
                }
                catch (HttpRequestException ex)
                {
                    LogPwnedPasswordApiError(logger, ex.Message, ex);
                    throw new PwnedPasswordsApiException("Error calling Pwned Passwords API.", ex);
                }
            }
            catch (Exception ex)
            {
                LogPwnedPasswordUnexpectedError(logger, ex.Message, ex);
                throw new PwnedPasswordsSearchException("Unexpected error during pwned password check.", ex);
            }
        }
    }
}