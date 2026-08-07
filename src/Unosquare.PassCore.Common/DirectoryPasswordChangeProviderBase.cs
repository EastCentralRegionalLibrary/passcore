using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Unosquare.PassCore.Common.Exceptions;
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

    /// <summary>
    /// Recovers a Win32 error code from a transport exception raised by this
    /// provider's directory operation.
    /// </summary>
    /// <remarks>
    /// The only genuinely provider-specific part of directory error handling
    /// is how a Win32 code is recovered from that provider's transport;
    /// everything downstream — classification, actor collapsing, and the
    /// choice of domain exception — is shared and lives in
    /// <see cref="DirectoryErrorTranslator"/>. The Active Directory provider's
    /// transport surfaces a <see cref="System.ComponentModel.Win32Exception"/>
    /// or a FACILITY_WIN32 HRESULT, which is exactly what the default
    /// implementation (<see cref="DirectoryErrorTranslator.TryGetWin32Code"/>)
    /// already handles, so it does not override this. The LDAP provider's
    /// transport instead carries the code inside an Active Directory extended
    /// error string, so it overrides this to parse that string.
    /// </remarks>
    /// <param name="exception">The exception raised by the directory operation.</param>
    /// <param name="win32Code">The extracted Win32 code.</param>
    /// <returns><see langword="true"/> when a code was found.</returns>
    protected virtual bool TryGetTransportWin32Code(Exception exception, out int win32Code) =>
        DirectoryErrorTranslator.TryGetWin32Code(exception, out win32Code);

    /// <summary>
    /// Translates a transport exception into the domain exception described
    /// by <see cref="DirectoryErrorTranslator"/>'s routing table, using
    /// <see cref="TryGetTransportWin32Code"/> to recover the provider-specific
    /// Win32 code and <see cref="ErrorDisclosureMode"/> for the configured
    /// disclosure posture.
    /// </summary>
    /// <param name="exception">The exception raised by the directory operation.</param>
    /// <param name="actor">Whose failure the exception describes.</param>
    /// <param name="failureClass">The actor-adjusted classification;
    /// <see cref="DirectoryFailureClass.Infrastructure"/> when no Win32 code
    /// could be recovered.</param>
    /// <returns>The domain exception to throw.</returns>
    protected Exception TranslateDirectoryException(
        Exception exception,
        DirectoryActor actor,
        out DirectoryFailureClass failureClass)
    {
        ArgumentNullException.ThrowIfNull(exception);

        if (TryGetTransportWin32Code(exception, out var win32Code))
        {
            failureClass = DirectoryErrorTranslator.ClassifyForActor(win32Code, actor);
            return DirectoryErrorTranslator.Translate(win32Code, ErrorDisclosureMode, actor, exception);
        }

        failureClass = DirectoryFailureClass.Infrastructure;
        return new DirectoryUnavailableException(DirectoryErrorTranslator.DirectoryFailureMessage, exception);
    }

    /// <summary>
    /// Convenience overload of
    /// <see cref="TranslateDirectoryException(Exception, DirectoryActor, out DirectoryFailureClass)"/>
    /// for callers that do not need the classification.
    /// </summary>
    /// <param name="exception">The exception raised by the directory operation.</param>
    /// <param name="actor">Whose failure the exception describes.</param>
    /// <returns>The domain exception to throw.</returns>
    protected Exception TranslateDirectoryException(Exception exception, DirectoryActor actor) =>
        TranslateDirectoryException(exception, actor, out _);

    /// <summary>
    /// Convenience overload of
    /// <see cref="TranslateDirectoryException(Exception, DirectoryActor, out DirectoryFailureClass)"/>
    /// for the common case of an end-user request, using
    /// <see cref="DirectoryActor.User"/>.
    /// </summary>
    /// <param name="exception">The exception raised by the directory operation.</param>
    /// <returns>The domain exception to throw.</returns>
    protected Exception TranslateDirectoryException(Exception exception) =>
        TranslateDirectoryException(exception, DirectoryActor.User, out _);

    /// <summary>
    /// The provider-specific body of a password change: everything up to, but
    /// not including, the terminal catch that both directory providers used to
    /// duplicate. Implementations keep whatever typed transport catch they
    /// need (e.g. the LDAP provider's <c>catch (LdapException)</c>) but must
    /// not add a final <see cref="PasswordChangeException"/>/<see cref="Exception"/>
    /// pair of their own — <see cref="ChangePasswordCore"/> supplies that.
    /// </summary>
    /// <param name="context">The password change context.</param>
    /// <param name="cancellationToken">A token to observe for cancellation.</param>
    protected abstract Task ChangeDirectoryPasswordCore(PasswordChangeContext context, CancellationToken cancellationToken);

    /// <inheritdoc />
    /// <remarks>
    /// <para>Both directory providers ended <c>ChangePasswordCore</c> with an
    /// identical pair of catch clauses, each carrying a comment that it had to
    /// match the other by hand. That duplication is collected here, sealed so
    /// neither provider can silently diverge from it again.</para>
    /// <para><b>The terminal catch constructs <see cref="DirectoryUnavailableException"/>
    /// directly, and must not call <see cref="TranslateDirectoryException(Exception)"/>
    /// or otherwise re-scan the exception chain for a Win32 code.</b> Per the
    /// error-routing matrix (see docs/error-routing-matrix.md, "Terminal
    /// catch"), speculative extraction does not belong here: any exception
    /// that carries a genuine directory code has already been handled at its
    /// own stage — a typed transport catch in
    /// <see cref="ChangeDirectoryPasswordCore"/>, or a service-account
    /// operation upstream of it. An exception reaching this catch is by
    /// definition unexpected and non-directory-typed, so it is classified as
    /// infrastructure unconditionally, exactly like the two duplicated
    /// implementations it replaces. This intentionally differs from the root
    /// <see cref="PasswordChangeProviderBase.ChangePasswordAsync"/> catch-all,
    /// which classifies an unexpected exception as
    /// <c>ApiErrorCode.Generic</c>: a directory provider's terminal fallback
    /// has always reported <c>LdapProblem</c> instead, and this preserves that
    /// existing behaviour rather than silently "correcting" it.</para>
    /// <para><b>This catch also swallows <see cref="OperationCanceledException"/>.</b>
    /// The root <see cref="PasswordChangeProviderBase.ChangePasswordAsync"/> has a
    /// dedicated <c>catch (OperationCanceledException)</c> ahead of its catch-all,
    /// which logs EventId 3 and rethrows; because that catch sits outside this
    /// method, a cancellation raised from within <see cref="ChangeDirectoryPasswordCore"/>
    /// never reaches it and instead falls into the generic <c>catch (Exception)</c>
    /// here, becoming a <see cref="DirectoryUnavailableException"/> reported as
    /// <c>LdapProblem</c> rather than being recognised as a cancellation. This is
    /// deliberate, not an oversight: it matches the pre-existing behaviour of both
    /// directory providers' terminal catches, which never distinguished
    /// <see cref="OperationCanceledException"/> either. It is also currently
    /// inert — neither directory provider observes the token it is given,
    /// since <see cref="PasswordChangeProviderBase.PerformPasswordChangeAsync"/>
    /// supplies none, so <paramref name="cancellationToken"/> here is always
    /// <see cref="CancellationToken.None"/> and no cancellation can actually
    /// occur. A future provider that genuinely honours the token should revisit
    /// this catch so a real cancellation is not mislabelled as a directory
    /// failure.</para>
    /// </remarks>
    protected sealed override async Task ChangePasswordCore(PasswordChangeContext context, CancellationToken cancellationToken)
    {
        try
        {
            await ChangeDirectoryPasswordCore(context, cancellationToken).ConfigureAwait(false);
        }
        catch (PasswordChangeException)
        {
            throw;
        }
        catch (Exception ex)
        {
            throw new DirectoryUnavailableException(DirectoryErrorTranslator.DirectoryFailureMessage, ex);
        }
    }
}
