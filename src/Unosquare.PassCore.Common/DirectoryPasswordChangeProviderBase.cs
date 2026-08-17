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
public abstract class DirectoryPasswordChangeProviderBase : PasswordChangeProviderBase, IGroupMembershipTester, IGroupMembershipResolver
{
    /// <inheritdoc />
    public async Task<bool> IsMemberOfGroupAsync(string username, string groupName)
    {
        // Added null guards here as intended so both provider implementations
        // inherit them. The AD provider previously lacked null guards, so it
        // gains them now.
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(groupName);

        var membership = await ResolveMembershipAsync(username).ConfigureAwait(false);
        return await membership.IsMemberOfAnyAsync(new[] { groupName }).ConfigureAwait(false);
    }

    /// <inheritdoc />
    public abstract Task<IResolvedGroupMembership> ResolveMembershipAsync(string username);

    /// <summary>
    /// Wraps a provider's membership evaluation in the shared
    /// <see cref="IResolvedGroupMembership"/> contract.
    /// </summary>
    /// <remarks>
    /// <para>This is how a provider returns a resolution: it supplies the evaluation
    /// and nothing else. The decision about what an undetermined membership means —
    /// throw as a service-account infrastructure failure, never answer
    /// <see langword="false"/> — is made here, once, for every provider.</para>
    /// <para>Both providers previously carried their own <c>IResolvedGroupMembership</c>
    /// implementation and their own copy of that decision, kept honest only by a
    /// source-text audit over each provider's file. Supplying the translation from the
    /// base removes the possibility of the two drifting.</para>
    /// </remarks>
    /// <param name="evaluate">Tests the resolved user against a set of group names.</param>
    /// <returns>A resolution presenting the shared bool-or-throw contract.</returns>
    protected IResolvedGroupMembership ResolveMembership(
        Func<IReadOnlyCollection<string>, Task<GroupMembershipAnswer>> evaluate) =>
        new ResolvedGroupMembership(
            evaluate,
            reason => TranslateDirectoryException(reason, DirectoryActor.ServiceAccount));

    /// <summary>
    /// Runs a service-account directory operation, guaranteeing that any
    /// failure surfaces as an infrastructure error rather than an end-user
    /// credential/existence/account-state error. This is the directory provider's
    /// counterpart to the LDAP provider's <c>BindAsServiceAccount</c>: both
    /// route through the shared <see cref="DirectoryErrorTranslator"/> with
    /// <see cref="DirectoryActor.ServiceAccount"/>, which is the single point
    /// enforcing "a service-account failure can never be reported as invalid
    /// credentials." Every service-account operation in this provider goes
    /// through this method, so a future maintainer adding one inherits the
    /// guarantee. Domain exceptions (should any arise) pass through unchanged.
    /// </summary>
    /// <typeparam name="T">The operation's result type.</typeparam>
    /// <param name="operation">A short label used for diagnostics logging.</param>
    /// <param name="correlationId">The request correlation ID, or null when unavailable.</param>
    /// <param name="action">The service-account operation to run.</param>
    /// <returns>The operation's result.</returns>
    protected T RunAsServiceAccount<T>(string operation, string? correlationId, Func<T> action)
    {
        ArgumentNullException.ThrowIfNull(action);

        try
        {
            return action();
        }
        catch (PasswordChangeException)
        {
            throw;
        }
        catch (Exception ex)
        {
            ServiceAccountFailure.Log(Logger, correlationId, operation, ServiceAccountHost(), ex);
            throw TranslateDirectoryException(ex, DirectoryActor.ServiceAccount);
        }
    }

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
    /// <param name="serviceAccountRequired">Whether a service account is required for this provider's configuration.</param>
    /// <param name="clientSettings">The client settings, or <see langword="null"/> for defaults.</param>
    /// <param name="policies">The password policies to evaluate, or <see langword="null"/> for none.</param>
    protected DirectoryPasswordChangeProviderBase(
        ILogger logger,
        IAppSettings settings,
        bool serviceAccountRequired,
        ClientSettings? clientSettings = null,
        IEnumerable<IPasswordPolicy>? policies = null)
        : base(logger, clientSettings, policies)
    {
        ArgumentNullException.ThrowIfNull(settings);
        Settings = settings;
        AppSettingsValidation.ValidateServiceAccount(settings, serviceAccountRequired);
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
    /// Whether this provider can perform an administrative reset at all —
    /// distinct from whether <see cref="IAppSettings.AllowAdministrativeReset"/>
    /// is enabled, which <see cref="AdministrativeReset.ShouldAttempt"/> checks
    /// separately. A provider overrides this to <see langword="false"/> when it
    /// has no service-account write path to reset with (the Active Directory
    /// provider in automatic-context mode) or when its normal write mechanism is
    /// already administrative and a distinct reset would be redundant (the LDAP
    /// provider outside the delete/add mechanism).
    /// </summary>
    protected virtual bool AdministrativeResetSupported => true;

    /// <summary>
    /// Runs the shared administrative-reset algorithm both directory providers
    /// used to implement identically: attempt the user-context change and, only
    /// when the failure is rescue-eligible, fall back to a service-account
    /// reset — logging every reset with <see cref="AdministrativeReset.LogPerformed"/>.
    /// </summary>
    /// <remarks>
    /// <para>See <see cref="PerformGatedBlockedWrite"/> for the pre-flight
    /// counterpart of this method, used when a caller already knows — without
    /// attempting the change — that the account is flagged so the user cannot
    /// change their own password. The two used to be one method taking a
    /// <c>changeBlockedByFlag</c> flag; splitting them means the impossible
    /// "blocked, but also try the doomed user-context change" state can no
    /// longer be expressed, and neither caller needs a throwaway closure to
    /// stand in for a change that must never run.</para>
    /// <para><b>Rescue eligibility</b> is
    /// <see cref="AdministrativeResetSupported"/> AND
    /// <see cref="AdministrativeReset.ShouldAttempt"/> with
    /// <see cref="IAppSettings.AllowAdministrativeReset"/>,
    /// <paramref name="currentPasswordVerified"/>, and the failure class
    /// recovered by
    /// <see cref="TranslateDirectoryException(Exception, DirectoryActor, out DirectoryFailureClass)"/>.
    /// Only <see cref="DirectoryFailureClass.ChangeNotPermitted"/> is ever
    /// rescuable; a reset never happens unless
    /// <paramref name="currentPasswordVerified"/> is <see langword="true"/> —
    /// an administrative reset without proof of the current password would be
    /// an account-takeover primitive.</para>
    /// <para><b>Why this takes delegates rather than exposing abstract write
    /// methods.</b> <c>AdProviderDirectoryWriteAuditTests</c> enforces the AD
    /// provider's write-capable invariants by scanning the TEXT of
    /// <c>PasswordChangeProvider.cs</c> for write-capable calls (<c>.Save(</c>,
    /// <c>.SetPassword(</c>, <c>.ChangePassword(</c>, <c>.Invoke(</c>, ...). If
    /// the actual write calls moved into this shared method, that audit would
    /// keep passing while guarding nothing — it never sees this file. Callers
    /// therefore pass closures whose bodies remain in the calling provider's own
    /// file, containing the real write calls unchanged; this method only decides
    /// *whether* and *which* closure runs. Do not restructure this so a write
    /// call migrates out of a provider's own file.</para>
    /// </remarks>
    /// <param name="context">The password change context.</param>
    /// <param name="currentPasswordVerified">Whether the user's current password
    /// was verified earlier in this request.</param>
    /// <param name="writeChangeAsUser">
    /// Performs the user-context password change. Any exception it throws is
    /// translated and, if rescue-eligible, swallowed in favor of
    /// <paramref name="writeResetAsService"/>; otherwise the translated
    /// exception is thrown. Any exception already a
    /// <see cref="PasswordChangeException"/> is rethrown unchanged rather than
    /// being retranslated.
    /// </param>
    /// <param name="writeResetAsService">
    /// Performs the administrative reset with the service account. Invoked only
    /// when the failure is rescue-eligible. Deliberately outside the
    /// <see langword="try"/>: an exception it throws propagates as-is rather
    /// than being swallowed or retranslated.
    /// </param>
    protected async Task PerformGatedPasswordWrite(
        PasswordChangeContext context,
        bool currentPasswordVerified,
        Func<Task> writeChangeAsUser,
        Func<Task> writeResetAsService)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(writeChangeAsUser);
        ArgumentNullException.ThrowIfNull(writeResetAsService);

        try
        {
            await writeChangeAsUser().ConfigureAwait(false);
        }
        catch (PasswordChangeException)
        {
            throw;
        }
        catch (Exception ex)
        {
            var translated = TranslateDirectoryException(ex, DirectoryActor.User, out var failureClass);

            if (!IsRescueEligible(currentPasswordVerified, failureClass))
                throw translated;

            await writeResetAsService().ConfigureAwait(false);
            AdministrativeReset.LogPerformed(Logger, context.CorrelationId, context.Username, translated);
        }
    }

    /// <summary>
    /// The pre-flight counterpart of <see cref="PerformGatedPasswordWrite"/>,
    /// used when a caller has already determined — without attempting the
    /// user-context change — that the account is flagged so the user cannot
    /// change their own password. Skips straight to the rescue decision using
    /// the synthesized <see cref="DirectoryErrorTranslator.CreateChangeNotPermittedError"/>
    /// as the gate's failure, and, if eligible, performs the reset and logs it
    /// with <see cref="AdministrativeReset.LogPerformed"/>; otherwise throws the
    /// synthesized error.
    /// </summary>
    /// <param name="context">The password change context.</param>
    /// <param name="currentPasswordVerified">Whether the user's current password
    /// was verified earlier in this request.</param>
    /// <param name="writeResetAsService">
    /// Performs the administrative reset with the service account. Invoked only
    /// when the block is rescue-eligible.
    /// </param>
    protected async Task PerformGatedBlockedWrite(
        PasswordChangeContext context,
        bool currentPasswordVerified,
        Func<Task> writeResetAsService)
    {
        ArgumentNullException.ThrowIfNull(context);
        ArgumentNullException.ThrowIfNull(writeResetAsService);

        var blocked = DirectoryErrorTranslator.CreateChangeNotPermittedError();

        if (!IsRescueEligible(currentPasswordVerified, DirectoryFailureClass.ChangeNotPermitted))
            throw blocked;

        await writeResetAsService().ConfigureAwait(false);
        AdministrativeReset.LogPerformed(Logger, context.CorrelationId, context.Username, blocked);
    }

    private bool IsRescueEligible(bool currentPasswordVerified, DirectoryFailureClass failureClass) =>
        AdministrativeResetSupported
        && AdministrativeReset.ShouldAttempt(Settings.AllowAdministrativeReset, currentPasswordVerified, failureClass);

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
