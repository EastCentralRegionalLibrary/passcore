using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PwnedPasswordsSearch;
using Unosquare.PassCore.Common;

namespace Unosquare.PassCore.PasswordProvider.Debug;

#if DEBUG
/// <summary>
/// Represents a debug password change provider that can be configured for testing and development.
/// </summary>
public class DebugPasswordChangeProvider : IPasswordChangeProvider
{
    private readonly IPwnedPasswordSearch _pwnedPasswordSearch;
    private readonly DebugProviderOptions _options;
    private readonly ILogger<DebugPasswordChangeProvider> _logger;

    /// <summary>
    /// Initializes a new instance of the <see cref="DebugPasswordChangeProvider"/> class.
    /// </summary>
    /// <param name="pwnedPasswordSearch">The pwned password search service.</param>
    /// <param name="options">The debug provider options.</param>
    /// <param name="logger">The logger.</param>
    public DebugPasswordChangeProvider(
        IPwnedPasswordSearch pwnedPasswordSearch,
        IOptions<DebugProviderOptions> options,
        ILogger<DebugPasswordChangeProvider> logger)
    {
        _pwnedPasswordSearch = pwnedPasswordSearch;
        _options = options.Value;
        _logger = logger;
    }

    /// <inheritdoc />
    public async Task<ApiErrorItem?> PerformPasswordChangeAsync(
        string username,
        string currentPassword,
        string newPassword,
        CancellationToken cancellationToken = default)
    {
        _logger.LogInformation("Debug password change requested for user: {Username}", username);

        if (_options.SimulateLatencyMs > 0)
        {
            _logger.LogDebug("Simulating latency of {Latency}ms", _options.SimulateLatencyMs);
            await Task.Delay(_options.SimulateLatencyMs, cancellationToken);
        }

        var currentUsername = username.Contains('@', System.StringComparison.Ordinal)
            ? username[..username.IndexOf('@', System.StringComparison.Ordinal)]
            : username;

        // Check for explicitly configured forced errors first
        if (_options.ForcedErrors != null && _options.ForcedErrors.TryGetValue(currentUsername, out var errorCode))
        {
            _logger.LogWarning("Forced error {ErrorCode} for username: {Username}", errorCode, currentUsername);
            return new ApiErrorItem(errorCode, $"Forced error {errorCode} for debug");
        }

        // Check for pwned password if enabled
        if (_options.EnablePwnedCheck)
        {
            if (await _pwnedPasswordSearch.IsPwnedPasswordAsync(newPassword))
            {
                _logger.LogWarning("Pwned password detected for user: {Username}", username);
                return new ApiErrorItem(ApiErrorCode.PwnedPassword);
            }
        }

        // Fallback to legacy hardcoded logic for convenience, or the DefaultErrorCode if set
        return currentUsername switch
        {
            "error" => new ApiErrorItem(ApiErrorCode.Generic, "Error"),
            "changeNotPermitted" => new ApiErrorItem(ApiErrorCode.ChangeNotPermitted),
            "fieldMismatch" => new ApiErrorItem(ApiErrorCode.FieldMismatch),
            "fieldRequired" => new ApiErrorItem(ApiErrorCode.FieldRequired),
            "invalidCaptcha" => new ApiErrorItem(ApiErrorCode.InvalidCaptcha),
            "invalidCredentials" => new ApiErrorItem(ApiErrorCode.InvalidCredentials),
            "invalidDomain" => new ApiErrorItem(ApiErrorCode.InvalidDomain),
            "userNotFound" => new ApiErrorItem(ApiErrorCode.UserNotFound),
            "ldapProblem" => new ApiErrorItem(ApiErrorCode.LdapProblem),
            "pwnedPassword" => new ApiErrorItem(ApiErrorCode.PwnedPassword),
            _ => _options.DefaultErrorCode.HasValue ? new ApiErrorItem(_options.DefaultErrorCode.Value) : null
        };
    }
}
#endif
