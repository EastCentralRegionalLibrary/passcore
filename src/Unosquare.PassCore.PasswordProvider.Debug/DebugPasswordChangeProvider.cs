using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using PwnedPasswordsSearch;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.PasswordProvider.Debug;

#if DEBUG
/// <summary>
/// Represents a debug password change provider that can be configured for testing and development.
/// </summary>
public class DebugPasswordChangeProvider : PasswordChangeProviderBase
{
    private readonly DebugProviderOptions _options;

    /// <summary>
    /// Initializes a new instance of the <see cref="DebugPasswordChangeProvider"/> class.
    /// </summary>
    /// <param name="options">The debug provider options.</param>
    /// <param name="logger">The logger.</param>
    /// <param name="policies">The password policies.</param>
    public DebugPasswordChangeProvider(
        IOptions<DebugProviderOptions> options,
        ILogger<DebugPasswordChangeProvider> logger,
        IEnumerable<IPasswordPolicy> policies)
        : base(logger, policies)
    {
        _options = options.Value;
    }

    /// <inheritdoc />
    protected override async Task ChangePasswordCore(
        PasswordChangeContext context,
        CancellationToken cancellationToken)
    {
        if (_options.SimulateLatencyMs > 0)
        {
            await Task.Delay(_options.SimulateLatencyMs, cancellationToken);
        }

        var username = context.Username;
        var currentUsername = username.Contains('@', System.StringComparison.Ordinal)
            ? username[..username.IndexOf('@', System.StringComparison.Ordinal)]
            : username;

        // Check for explicitly configured forced errors first
        if (_options.ForcedErrors != null && _options.ForcedErrors.TryGetValue(currentUsername, out var errorCode))
        {
            throw new PasswordPolicyViolationException($"Forced error {errorCode} for debug", errorCode);
        }

        // Fallback to legacy hardcoded logic for convenience, or the DefaultErrorCode if set
        var apiErrorCode = currentUsername switch
        {
            "error" => ApiErrorCode.Generic,
            "changeNotPermitted" => ApiErrorCode.ChangeNotPermitted,
            "fieldMismatch" => ApiErrorCode.FieldMismatch,
            "fieldRequired" => ApiErrorCode.FieldRequired,
            "invalidCaptcha" => ApiErrorCode.InvalidCaptcha,
            "invalidCredentials" => ApiErrorCode.InvalidCredentials,
            "invalidDomain" => ApiErrorCode.InvalidDomain,
            "userNotFound" => ApiErrorCode.UserNotFound,
            "ldapProblem" => ApiErrorCode.LdapProblem,
            "pwnedPassword" => ApiErrorCode.PwnedPassword,
            _ => _options.DefaultErrorCode
        };

        if (apiErrorCode.HasValue)
        {
            throw apiErrorCode.Value switch
            {
                ApiErrorCode.InvalidCredentials => new InvalidCredentialsException(),
                ApiErrorCode.UserNotFound => new UserNotFoundException(),
                ApiErrorCode.LdapProblem => new DirectoryUnavailableException("LDAP problem", new System.Exception("Debug LDAP problem")),
                _ => new PasswordPolicyViolationException($"Debug error {apiErrorCode.Value}", apiErrorCode.Value)
            };
        }
    }
}
#endif
