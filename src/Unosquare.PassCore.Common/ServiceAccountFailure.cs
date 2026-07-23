using System;
using Microsoft.Extensions.Logging;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Shared, uniform logging for failures that arise while a provider is acting
/// as its own service account (connecting, binding, or resolving against the
/// directory). Such a failure is operator-actionable — a misconfigured
/// service-account credential, a missing directory permission, or a
/// connectivity problem — yet the end user receives only a curated
/// infrastructure response with no server detail. This helper puts the real
/// diagnosis in the log at Warning: correlation ID (when available), the
/// operation, the host, and the underlying Win32 code when one can be
/// recovered.
/// </summary>
public static class ServiceAccountFailure
{
    private static readonly Action<ILogger, string?, string, string, string, Exception?> LogDefinition =
        LoggerMessage.Define<string?, string, string, string>(
            LogLevel.Warning,
            new EventId(111, "ServiceAccountFailure"),
            "[{CorrelationId}] Directory operation '{Operation}' failed while acting as the " +
            "configured service account (host: {Host}, underlying code: {UnderlyingCode}). This is " +
            "an operator-actionable infrastructure condition — check the service-account " +
            "credentials, its directory permissions, and connectivity to the host. The end user " +
            "receives a generic directory-unavailable response; no account or credential detail " +
            "is disclosed.");

    /// <summary>
    /// Logs a service-account operation failure at Warning.
    /// </summary>
    /// <param name="logger">The provider's logger.</param>
    /// <param name="correlationId">The request correlation ID, when the calling
    /// path has one; <see langword="null"/> otherwise (e.g. group-membership
    /// lookups that carry no request context).</param>
    /// <param name="operation">A short label for the operation that failed.</param>
    /// <param name="host">The directory host involved, when known.</param>
    /// <param name="failure">The underlying failure, whose chain is scanned for
    /// a Win32 code and which is passed to the logger for full detail.</param>
    public static void Log(
        ILogger logger,
        string? correlationId,
        string operation,
        string? host,
        Exception failure)
    {
        ArgumentNullException.ThrowIfNull(logger);
        ArgumentNullException.ThrowIfNull(failure);

        var underlyingCode = DirectoryErrorTranslator.TryGetWin32Code(failure, out var code)
            ? $"0x{code:X}"
            : "unknown";

        LogDefinition(logger, correlationId ?? "n/a", operation, host ?? "n/a", underlyingCode, failure);
    }
}
