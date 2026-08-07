using System;
using System.Collections.Generic;
using Microsoft.Extensions.Logging;
using Unosquare.PassCore.Common.Models;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Base class for password change providers that talk to a directory with a
/// configured service account. Sits between <see cref="PasswordChangeProviderBase"/>
/// and the two shipped directory providers, and owns the behaviour they were
/// previously obliged to reimplement identically.
/// </summary>
/// <remarks>
/// <para><b>Why this is a separate layer rather than part of
/// <see cref="PasswordChangeProviderBase"/>.</b> The root base serves every
/// provider, including the Debug provider, whose options deliberately do not
/// implement <see cref="IAppSettings"/>: it has no service account, no
/// directory host, and no disclosure posture to read from configuration.
/// Pushing <see cref="Settings"/> up would either force a meaningless
/// <see cref="IAppSettings"/> implementation onto it or make the property
/// nullable for everyone. A separate layer keeps the directory concerns with
/// the directory providers and leaves the Debug path untouched.</para>
/// <para><b>Why it matters that this lives in Common.</b> The Active Directory
/// provider targets <c>net8.0-windows</c> and its entire implementation sits
/// inside <c>#if WINDOWS</c>, so it cannot be referenced, loaded, or exercised
/// from the cross-platform test suite at all — its guarantees are currently
/// enforced by source-text audits (see
/// <c>AdProviderDirectoryWriteAuditTests</c>) rather than by behavioural
/// tests. Every decision moved from a provider into this class becomes
/// testable for both providers at once.</para>
/// </remarks>
public abstract class DirectoryPasswordChangeProviderBase : PasswordChangeProviderBase
{
    /// <summary>
    /// The provider's directory settings. Held as <see cref="IAppSettings"/>
    /// rather than the concrete options type so that shared logic here can read
    /// the settings both providers agree on; each provider keeps its own typed
    /// reference for the options only it understands.
    /// </summary>
    protected IAppSettings Settings { get; }

    /// <summary>
    /// Initializes the shared directory-provider state.
    /// </summary>
    /// <param name="logger">The provider's logger.</param>
    /// <param name="settings">The directory settings; required.</param>
    /// <param name="clientSettings">The client settings, or <see langword="null"/> for defaults.</param>
    /// <param name="policies">The password policies to evaluate, or <see langword="null"/> for none.</param>
    protected DirectoryPasswordChangeProviderBase(
        ILogger logger,
        IAppSettings settings,
        ClientSettings? clientSettings = null,
        IEnumerable<IPasswordPolicy>? policies = null)
        : base(logger, clientSettings, policies)
    {
        ArgumentNullException.ThrowIfNull(settings);
        Settings = settings;
    }

    /// <inheritdoc />
    /// <remarks>
    /// Both directory providers carried an identical override reading the same
    /// property off their own options type. The posture is a shared
    /// <see cref="IAppSettings"/> concern, so it is read once here; see
    /// <see cref="ErrorDisclosureMode"/> for what the two modes trade off.
    /// </remarks>
    public override ErrorDisclosureMode ErrorDisclosureMode => Settings.ErrorDisclosureMode;

    /// <summary>
    /// Describes the directory host used for service-account operations, for
    /// diagnostics logging only (see <see cref="ServiceAccountFailure.Log"/>).
    /// </summary>
    /// <remarks>
    /// The default names every configured host, which is right for a provider
    /// that tries them in turn. A provider whose connection model differs — the
    /// AD provider binds one host, or none at all in automatic-context mode —
    /// overrides this. It is diagnostic text and takes no part in any routing
    /// decision.
    /// </remarks>
    /// <returns>A short description of the host, never <see langword="null"/>.</returns>
    protected virtual string ServiceAccountHost() =>
        Settings.LdapHostnames is { Length: > 0 } hostnames
            ? string.Join(", ", hostnames)
            : "n/a";
}
