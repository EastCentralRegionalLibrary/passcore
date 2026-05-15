using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;

namespace Unosquare.PassCore.PasswordProvider.Debug;

/// <summary>
/// A configurable, in-memory password change provider used for testing,
/// development and E2E scenarios. Supports forced error injection by
/// username and simulated latency.
/// </summary>
public class DebugPasswordChangeProvider : PasswordChangeProviderBase
{
    private static readonly IReadOnlyDictionary<string, ApiErrorCode> LegacyForcedErrors =
        new Dictionary<string, ApiErrorCode>(StringComparer.OrdinalIgnoreCase)
        {
            ["error"] = ApiErrorCode.Generic,
            ["changeNotPermitted"] = ApiErrorCode.ChangeNotPermitted,
            ["fieldMismatch"] = ApiErrorCode.FieldMismatch,
            ["fieldRequired"] = ApiErrorCode.FieldRequired,
            ["invalidCaptcha"] = ApiErrorCode.InvalidCaptcha,
            ["invalidCredentials"] = ApiErrorCode.InvalidCredentials,
            ["invalidDomain"] = ApiErrorCode.InvalidDomain,
            ["userNotFound"] = ApiErrorCode.UserNotFound,
            ["ldapProblem"] = ApiErrorCode.LdapProblem,
            ["pwnedPassword"] = ApiErrorCode.PwnedPassword,
            ["complexPassword"] = ApiErrorCode.ComplexPassword,
            ["minimumScore"] = ApiErrorCode.MinimumScore,
            ["minimumDistance"] = ApiErrorCode.MinimumDistance,
        };

    private readonly DebugProviderOptions _options;

    public DebugPasswordChangeProvider(
        IOptions<DebugProviderOptions> options,
        IOptions<ClientSettings> clientSettings,
        ILogger<DebugPasswordChangeProvider> logger,
        IEnumerable<IPasswordPolicy> policies)
        : base(logger, clientSettings?.Value, policies)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options.Value;
    }

    /// <inheritdoc />
    protected override async Task ChangePasswordCore(
        PasswordChangeContext context,
        CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(context);

        if (_options.SimulateLatencyMs > 0)
            await Task.Delay(_options.SimulateLatencyMs, cancellationToken).ConfigureAwait(false);

        var resolvedErrorCode = ResolveErrorCode(context.Username);
        if (resolvedErrorCode is not { } errorCode)
            return;

        throw errorCode switch
        {
            ApiErrorCode.InvalidCredentials => new InvalidCredentialsException("Debug: invalid credentials"),
            ApiErrorCode.UserNotFound => new UserNotFoundException("Debug: user not found"),
            ApiErrorCode.LdapProblem => new DirectoryUnavailableException(
                "Debug: simulated LDAP failure",
                new InvalidOperationException("Debug LDAP problem")),
            _ => new PasswordPolicyViolationException($"Debug error {errorCode}", errorCode),
        };
    }

    private ApiErrorCode? ResolveErrorCode(string username)
    {
        var localPart = StripDomain(username);

        if (_options.ForcedErrors is { Count: > 0 } &&
            _options.ForcedErrors.TryGetValue(localPart, out var configured))
        {
            return configured;
        }

        if (LegacyForcedErrors.TryGetValue(localPart, out var legacy))
            return legacy;

        return _options.DefaultErrorCode;
    }

    private static string StripDomain(string username)
    {
        var at = username.IndexOf('@', StringComparison.Ordinal);
        return at < 0 ? username : username[..at];
    }
}
