using System;
using System.ComponentModel;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// Exercises <see cref="DirectoryPasswordChangeProviderBase"/>'s shared
/// administrative-reset gate — <c>PerformGatedPasswordWrite</c> and its
/// pre-flight counterpart <c>PerformGatedBlockedWrite</c> — directly against a
/// stub subclass. These are the single place both directory providers now
/// delegate the "attempt the user-context change, fall back to a
/// service-account reset only when rescue-eligible" algorithm to. This is the
/// most security-sensitive seam in the two providers: it decides whether a
/// password is ever set administratively.
/// </summary>
public class PerformGatedPasswordWriteTests
{
    private sealed class FakeAppSettings : IAppSettings
    {
        public ErrorDisclosureMode ErrorDisclosureMode { get; set; }

        public bool AllowAdministrativeReset { get; set; }

        public string DefaultDomain { get; set; } = string.Empty;

        public int LdapPort { get; set; }

        public string[] LdapHostnames { get; set; } = Array.Empty<string>();

        public string LdapPassword { get; set; } = string.Empty;

        public string LdapUsername { get; set; } = string.Empty;
    }

    /// <summary>
    /// A minimal directory provider whose only job is to expose
    /// <c>PerformGatedPasswordWrite</c> / <c>PerformGatedBlockedWrite</c> to
    /// the test and to let each test control
    /// <see cref="AdministrativeResetSupported"/> and the exception thrown by
    /// the change delegate, using the real <see cref="Win32Exception"/> /
    /// FACILITY_WIN32 translation path the shipped providers rely on.
    /// </summary>
    private sealed class StubProvider : DirectoryPasswordChangeProviderBase
    {
        private readonly bool _administrativeResetSupported;

        public StubProvider(IAppSettings settings, ILogger logger, bool administrativeResetSupported = true)
            : base(logger, settings, false)
        {
            _administrativeResetSupported = administrativeResetSupported;
        }

        protected override bool AdministrativeResetSupported => _administrativeResetSupported;

        protected override Task<int?> ReadMinPwdLength() => Task.FromResult<int?>(null);

        public override Task<IResolvedGroupMembership> ResolveMembershipAsync(string username) =>
            throw new NotImplementedException();

        protected override Task ChangeDirectoryPasswordCore(PasswordChangeContext context, CancellationToken cancellationToken) =>
            Task.CompletedTask;

        public int ChangeInvocations { get; private set; }

        public int ResetInvocations { get; private set; }

        public Task RunGatedWrite(
            PasswordChangeContext context,
            bool currentPasswordVerified,
            Exception? changeFailure,
            Exception? resetFailure = null)
        {
            return PerformGatedPasswordWrite(
                context,
                currentPasswordVerified,
                writeChangeAsUser: () =>
                {
                    ChangeInvocations++;
                    if (changeFailure is not null)
                        throw changeFailure;
                    return Task.CompletedTask;
                },
                writeResetAsService: () =>
                {
                    ResetInvocations++;
                    if (resetFailure is not null)
                        throw resetFailure;
                    return Task.CompletedTask;
                });
        }

        public Task RunGatedBlockedWrite(
            PasswordChangeContext context,
            bool currentPasswordVerified,
            Exception? resetFailure = null)
        {
            return PerformGatedBlockedWrite(
                context,
                currentPasswordVerified,
                writeResetAsService: () =>
                {
                    ResetInvocations++;
                    if (resetFailure is not null)
                        throw resetFailure;
                    return Task.CompletedTask;
                });
        }
    }

    private static PasswordChangeContext MakeContext(string correlationId = "corr-1") =>
        new("someone", "current-pw", "new-pw", new ClientSettings(), correlationId);

    private static StubProvider MakeProvider(
        bool allowAdministrativeReset,
        CapturingLogger? logger = null,
        bool administrativeResetSupported = true,
        ErrorDisclosureMode mode = ErrorDisclosureMode.Hardened) =>
        new(
            new FakeAppSettings { AllowAdministrativeReset = allowAdministrativeReset, ErrorDisclosureMode = mode },
            logger ?? new CapturingLogger(),
            administrativeResetSupported);

    // 0x8C3: NERR_PasswordCantChange, classified as ChangeNotPermitted.
    private static Exception ChangeNotPermittedFailure() => new Win32Exception(0x8C3);

    // 0x52D: history/minimum-age rejection, classified as NewPasswordPolicy.
    private static Exception NewPasswordPolicyFailure() => new Win32Exception(0x52D);

    // EventId 110 is where AdministrativeReset.LogPerformed writes; asserted
    // directly (rather than just "was there a log entry") so a future change
    // to the wrong EventId, still logging *something*, would be caught here.
    private const int AdministrativeResetLogPerformedEventId = 110;

    private static void AssertSingleResetLogEntry(CapturingLogger logger, string correlationId, Exception translatedFailure)
    {
        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal(AdministrativeResetLogPerformedEventId, entry.EventId.Id);
        Assert.Contains(correlationId, entry.Message, StringComparison.Ordinal);
        Assert.Contains("ADMINISTRATIVE PASSWORD RESET", entry.Message, StringComparison.Ordinal);
        Assert.Same(translatedFailure, entry.Exception);
    }

    [Fact]
    public async Task BlockedByFlag_NotEligible_ThrowsChangeNotPermitted_ResetNeverInvoked()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: false, logger: logger);
        var context = MakeContext();

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => provider.RunGatedBlockedWrite(context, currentPasswordVerified: true));

        Assert.Equal(ApiErrorCode.ChangeNotPermitted, ex.ErrorCode);
        Assert.Equal(0, provider.ChangeInvocations);
        Assert.Equal(0, provider.ResetInvocations);
        Assert.Empty(logger.Entries);
    }

    [Fact]
    public async Task BlockedByFlag_Eligible_ResetInvokedOnce_ChangeNeverInvoked_AndLoggedExactlyOnce()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: true, logger: logger);
        var context = MakeContext(correlationId: "blocked-corr-id");

        await provider.RunGatedBlockedWrite(context, currentPasswordVerified: true);

        Assert.Equal(1, provider.ResetInvocations);
        Assert.Equal(0, provider.ChangeInvocations);

        var entry = Assert.Single(logger.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Equal(AdministrativeResetLogPerformedEventId, entry.EventId.Id);
        Assert.Contains("blocked-corr-id", entry.Message, StringComparison.Ordinal);
        Assert.Contains("ADMINISTRATIVE PASSWORD RESET", entry.Message, StringComparison.Ordinal);
        Assert.IsType<PasswordPolicyViolationException>(entry.Exception);
    }

    /// <summary>
    /// FIX 6(c): the pre-flight account-takeover guard. A block is otherwise
    /// eligible (option enabled), but without proof of the current password in
    /// THIS request, no reset may run — not even for the pre-flight (detected
    /// flag) path, which had no test for this before.
    /// </summary>
    [Fact]
    public async Task BlockedByFlag_CredentialsNotVerified_ThrowsAndNeverResets()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: true, logger: logger);
        var context = MakeContext();

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => provider.RunGatedBlockedWrite(context, currentPasswordVerified: false));

        Assert.Equal(ApiErrorCode.ChangeNotPermitted, ex.ErrorCode);
        Assert.Equal(0, provider.ResetInvocations);
        Assert.Empty(logger.Entries);
    }

    [Fact]
    public async Task ChangeSucceeds_NeitherResetNorThrow_NothingLogged()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: true, logger: logger);
        var context = MakeContext();

        await provider.RunGatedWrite(context, currentPasswordVerified: true, changeFailure: null);

        Assert.Equal(1, provider.ChangeInvocations);
        Assert.Equal(0, provider.ResetInvocations);
        Assert.Empty(logger.Entries);
    }

    [Fact]
    public async Task ChangeFails_ChangeNotPermittedClass_Eligible_ResetInvoked_AndLoggedExactlyOnce()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: true, logger: logger);
        var context = MakeContext(correlationId: "change-corr-id");

        await provider.RunGatedWrite(context, currentPasswordVerified: true, changeFailure: ChangeNotPermittedFailure());

        Assert.Equal(1, provider.ChangeInvocations);
        Assert.Equal(1, provider.ResetInvocations);

        var entry = Assert.Single(logger.Entries);
        AssertSingleResetLogEntry(logger, "change-corr-id", entry.Exception!);
    }

    /// <summary>
    /// The account-takeover guard: even a rescuable failure class must not
    /// reset when the current password was never verified this request.
    /// </summary>
    [Fact]
    public async Task ChangeFails_ChangeNotPermittedClass_CredentialsNotVerified_ThrowsAndNeverResets()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: true, logger: logger);
        var context = MakeContext();
        var failure = ChangeNotPermittedFailure();

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => provider.RunGatedWrite(context, currentPasswordVerified: false, changeFailure: failure));

        Assert.Equal(ApiErrorCode.ChangeNotPermitted, ex.ErrorCode);
        Assert.Equal(1, provider.ChangeInvocations);
        Assert.Equal(0, provider.ResetInvocations);
        Assert.Empty(logger.Entries);
    }

    /// <summary>
    /// Intentional new-password policy (history, minimum age, complexity) is
    /// always honored — only <see cref="DirectoryFailureClass.ChangeNotPermitted"/>
    /// is ever rescuable.
    /// </summary>
    [Fact]
    public async Task ChangeFails_NewPasswordPolicyClass_Eligible_ThrowsAndNeverResets()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: true, logger: logger);
        var context = MakeContext();
        var failure = NewPasswordPolicyFailure();

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => provider.RunGatedWrite(context, currentPasswordVerified: true, changeFailure: failure));

        Assert.Equal(ApiErrorCode.ComplexPassword, ex.ErrorCode);
        Assert.Equal(1, provider.ChangeInvocations);
        Assert.Equal(0, provider.ResetInvocations);
        Assert.Empty(logger.Entries);
    }

    [Fact]
    public async Task AdministrativeResetNotSupported_ThrowsAndNeverResets_EvenWhenOtherwiseEligible()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: true, logger: logger, administrativeResetSupported: false);
        var context = MakeContext();
        var failure = ChangeNotPermittedFailure();

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => provider.RunGatedWrite(context, currentPasswordVerified: true, changeFailure: failure));

        Assert.Equal(ApiErrorCode.ChangeNotPermitted, ex.ErrorCode);
        Assert.Equal(1, provider.ChangeInvocations);
        Assert.Equal(0, provider.ResetInvocations);
        Assert.Empty(logger.Entries);
    }

    /// <summary>
    /// Same as <see cref="AdministrativeResetNotSupported_ThrowsAndNeverResets_EvenWhenOtherwiseEligible"/>
    /// for the pre-flight (blocked-by-flag) path, since it shares the same
    /// eligibility computation.
    /// </summary>
    [Fact]
    public async Task AdministrativeResetNotSupported_BlockedByFlag_ThrowsAndNeverResets()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: true, logger: logger, administrativeResetSupported: false);
        var context = MakeContext();

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => provider.RunGatedBlockedWrite(context, currentPasswordVerified: true));

        Assert.Equal(ApiErrorCode.ChangeNotPermitted, ex.ErrorCode);
        Assert.Equal(0, provider.ChangeInvocations);
        Assert.Equal(0, provider.ResetInvocations);
        Assert.Empty(logger.Entries);
    }

    /// <summary>
    /// FIX 6(a): an exception the shared translator cannot recover a Win32 code
    /// from becomes <see cref="DirectoryUnavailableException"/>, classified
    /// <see cref="DirectoryFailureClass.Infrastructure"/> — never rescuable —
    /// and the reset is never attempted.
    /// </summary>
    [Fact]
    public async Task ChangeFails_UntranslatableException_BecomesDirectoryUnavailable_ResetNeverInvoked()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: true, logger: logger);
        var context = MakeContext();
        var failure = new InvalidOperationException("not a directory error at all");

        var ex = await Assert.ThrowsAsync<DirectoryUnavailableException>(
            () => provider.RunGatedWrite(context, currentPasswordVerified: true, changeFailure: failure));

        Assert.Equal(DirectoryErrorTranslator.DirectoryFailureMessage, ex.Message);
        Assert.Same(failure, ex.InnerException);
        Assert.Equal(1, provider.ChangeInvocations);
        Assert.Equal(0, provider.ResetInvocations);
        Assert.Empty(logger.Entries);
    }

    /// <summary>
    /// FIX 3: an already-curated <see cref="PasswordChangeException"/> thrown by
    /// the change closure must reach the caller unwrapped, not be retranslated
    /// into a generic <see cref="DirectoryUnavailableException"/> by the broad
    /// catch. Uses a class other than <see cref="ChangeNotPermittedFailure"/>'s
    /// shape so a pass here cannot be explained by coincidental rescue logic.
    /// </summary>
    [Fact]
    public async Task ChangeFails_AlreadyCuratedPasswordChangeException_ReachesCallerUnwrapped()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: true, logger: logger);
        var context = MakeContext();
        var curated = new InvalidCredentialsException("already curated");

        var ex = await Assert.ThrowsAsync<InvalidCredentialsException>(
            () => provider.RunGatedWrite(context, currentPasswordVerified: true, changeFailure: curated));

        Assert.Same(curated, ex);
        Assert.Equal(0, provider.ResetInvocations);
        Assert.Empty(logger.Entries);
    }

    /// <summary>
    /// FIX 6(b): the reset closure sits deliberately OUTSIDE the gate's
    /// <see langword="try"/>, so an exception it throws must propagate exactly
    /// as thrown — not be swallowed, and not be retranslated the way a change
    /// failure is.
    /// </summary>
    [Fact]
    public async Task ResetThrows_PropagatesUnchanged_NotSwallowedOrRetranslated()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: true, logger: logger);
        var context = MakeContext();
        var resetFailure = new InvalidOperationException("the reset closure itself blew up");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.RunGatedWrite(
                context,
                currentPasswordVerified: true,
                changeFailure: ChangeNotPermittedFailure(),
                resetFailure: resetFailure));

        Assert.Same(resetFailure, ex);
        Assert.Equal(1, provider.ResetInvocations);

        // The reset closure threw before LogPerformed could run, so nothing
        // was logged — a thrown reset is not a "reset performed".
        Assert.Empty(logger.Entries);
    }

    /// <summary>
    /// Same as <see cref="ResetThrows_PropagatesUnchanged_NotSwallowedOrRetranslated"/>
    /// for the pre-flight (blocked-by-flag) path.
    /// </summary>
    [Fact]
    public async Task BlockedByFlag_ResetThrows_PropagatesUnchanged()
    {
        var logger = new CapturingLogger();
        var provider = MakeProvider(allowAdministrativeReset: true, logger: logger);
        var context = MakeContext();
        var resetFailure = new InvalidOperationException("the reset closure itself blew up");

        var ex = await Assert.ThrowsAsync<InvalidOperationException>(
            () => provider.RunGatedBlockedWrite(context, currentPasswordVerified: true, resetFailure: resetFailure));

        Assert.Same(resetFailure, ex);
        Assert.Equal(1, provider.ResetInvocations);
        Assert.Empty(logger.Entries);
    }
}
