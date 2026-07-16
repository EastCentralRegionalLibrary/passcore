using System;
using System.ComponentModel;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Classifies the directory conditions behind a Win32/AD error code so
/// providers route identical conditions identically.
/// </summary>
public enum DirectoryFailureClass
{
    /// <summary>
    /// Infrastructure or unrecognized failures (DC unreachable, access denied,
    /// uncataloged codes). The safe default for anything unclassified.
    /// </summary>
    Infrastructure = 0,

    /// <summary>
    /// The caller's current credentials are wrong (0x56, 0x52B, 0x52E).
    /// </summary>
    Credentials,

    /// <summary>
    /// The account does not exist or the name is malformed (0x523, 0x525).
    /// </summary>
    Existence,

    /// <summary>
    /// The account exists but is unusable: disabled, locked out, expired,
    /// or restricted by hours/workstation/policy (0x52F, 0x530, 0x531,
    /// 0x533, 0x701, 0x775).
    /// </summary>
    AccountState,

    /// <summary>
    /// The new password was rejected by domain policy: length, complexity,
    /// character rules, history, or minimum age (0x52C, 0x52D, 0x8C4,
    /// 0x8C5, 0x8C6).
    /// </summary>
    NewPasswordPolicy,

    /// <summary>
    /// The account is flagged so its password cannot be changed (0x8C3).
    /// </summary>
    ChangeNotPermitted,

    /// <summary>
    /// The current password is correct but expired or flagged
    /// must-change-at-next-logon (0x532, 0x773). Providers treat this as
    /// successful proof of the current password during verification.
    /// </summary>
    PasswordExpiredOrMustChange,
}

/// <summary>
/// The single translation point from Win32/AD error semantics to the domain
/// exceptions that <see cref="ApiErrorMapper"/> turns into wire-level
/// <see cref="ApiErrorItem"/>s. Providers own only transport-specific
/// extraction (parsing an LDAP extended-error message, unwrapping an HRESULT)
/// and must delegate routing here so identical directory conditions produce
/// identical results across providers. Every entry point requires an
/// <see cref="ErrorDisclosureMode"/>, so no caller can route without choosing
/// the configured posture.
///
/// Routing table (per <see cref="ErrorDisclosureMode"/>):
/// <list type="bullet">
/// <item><see cref="DirectoryFailureClass.Credentials"/> and
/// <see cref="DirectoryFailureClass.PasswordExpiredOrMustChange"/> →
/// <see cref="InvalidCredentialsException"/> with the uniform
/// <see cref="InvalidCredentialsMessage"/> in both modes.</item>
/// <item><see cref="DirectoryFailureClass.Existence"/> → hardened:
/// <see cref="InvalidCredentialsException"/> (indistinguishable from a wrong
/// password); informative: <see cref="UserNotFoundException"/> with
/// <see cref="UserNotFoundMessage"/>.</item>
/// <item><see cref="DirectoryFailureClass.AccountState"/> → hardened:
/// <see cref="InvalidCredentialsException"/>; informative:
/// <see cref="PasswordPolicyViolationException"/> with
/// <see cref="ApiErrorCode.ChangeNotPermitted"/> and
/// <see cref="AccountStateMessage"/> ("stop retrying, contact IT").</item>
/// <item><see cref="DirectoryFailureClass.NewPasswordPolicy"/> →
/// <see cref="PasswordPolicyViolationException"/> with an explicit
/// <see cref="ApiErrorCode.ComplexPassword"/> in both modes (0x52C and 0x52D
/// deliberately collapse into that code).</item>
/// <item><see cref="DirectoryFailureClass.ChangeNotPermitted"/> →
/// <see cref="PasswordPolicyViolationException"/> with
/// <see cref="ApiErrorCode.ChangeNotPermitted"/> in both modes (this code is
/// only produced by the directory after the caller proved the current
/// password).</item>
/// <item><see cref="DirectoryFailureClass.Infrastructure"/> and every
/// uncataloged code → <see cref="DirectoryUnavailableException"/> in both
/// modes.</item>
/// </list>
/// Exception messages are fixed curated strings; the specific code survives
/// only in the inner exception, which reaches logs but never the wire. In
/// hardened mode the credentials/existence/account-state rows are
/// byte-identical on the wire (same code, same message).
/// </summary>
public static class DirectoryErrorTranslator
{
    /// <summary>
    /// Uniform wire message for every condition routed to
    /// <see cref="InvalidCredentialsException"/>, chosen so wrong-password,
    /// unknown-user and unusable-account responses are indistinguishable.
    /// </summary>
    public const string InvalidCredentialsMessage = "Invalid username or password";

    /// <summary>
    /// Wire message for new-password policy rejections. Deliberately covers
    /// history and minimum-age alongside length/complexity because 0x52C and
    /// 0x52D collapse into <see cref="ApiErrorCode.ComplexPassword"/>.
    /// </summary>
    public const string NewPasswordPolicyMessage =
        "The new password does not meet the length, complexity, history, or minimum-age requirements of the domain";

    /// <summary>
    /// Wire message for accounts whose password cannot be changed.
    /// </summary>
    public const string ChangeNotPermittedMessage = "The password for this account cannot be changed";

    /// <summary>
    /// Wire message for infrastructure and unrecognized directory failures.
    /// Intentionally carries no server diagnostic text.
    /// </summary>
    public const string DirectoryFailureMessage =
        "The directory service could not complete the password change request";

    /// <summary>
    /// Wire message for unknown users in
    /// <see cref="ErrorDisclosureMode.Informative"/> mode only.
    /// </summary>
    public const string UserNotFoundMessage = "User not found";

    /// <summary>
    /// Wire message for unusable accounts (locked, disabled, expired,
    /// hours/workstation-restricted) in
    /// <see cref="ErrorDisclosureMode.Informative"/> mode only.
    /// </summary>
    public const string AccountStateMessage =
        "This account cannot change its password at this time. Contact your administrator or IT help desk";

    /// <summary>
    /// Classifies a Win32 error code via the <see cref="Win32ErrorCode"/>
    /// catalog. Uncataloged codes degrade to
    /// <see cref="DirectoryFailureClass.Infrastructure"/>; never throws.
    /// </summary>
    /// <param name="win32Code">The Win32 error code.</param>
    /// <returns>The failure classification.</returns>
    public static DirectoryFailureClass Classify(int win32Code) =>
        Win32ErrorCode.ByCode(win32Code)?.FailureClass ?? DirectoryFailureClass.Infrastructure;

    /// <summary>
    /// Indicates whether the code means the current password was correct but
    /// expired (0x532) or must change at next logon (0x773) — the shared
    /// definition of the "allow the change to proceed" verification outcome,
    /// kept here so the two providers cannot drift apart again. Accepts codes
    /// from any transport (LDAP data subcodes, LogonUser last-error values).
    /// </summary>
    /// <param name="win32Code">The Win32 error code.</param>
    /// <returns><see langword="true"/> for 0x532/0x773.</returns>
    public static bool IsPasswordExpiredOrMustChange(int win32Code) =>
        Classify(win32Code) == DirectoryFailureClass.PasswordExpiredOrMustChange;

    /// <summary>
    /// Translates a Win32 error code to the domain exception described in the
    /// class-level routing table, applying the configured disclosure posture.
    /// </summary>
    /// <param name="win32Code">The Win32 error code.</param>
    /// <param name="disclosureMode">The configured disclosure posture.</param>
    /// <param name="innerException">The transport exception, preserved for logs.</param>
    /// <returns>The domain exception to throw.</returns>
    public static Exception Translate(
        int win32Code,
        ErrorDisclosureMode disclosureMode,
        Exception? innerException = null)
    {
        return Classify(win32Code) switch
        {
            DirectoryFailureClass.Credentials or
            DirectoryFailureClass.PasswordExpiredOrMustChange =>
                InvalidCredentials(innerException),
            DirectoryFailureClass.Existence =>
                CreateUserNotFoundError(disclosureMode, innerException),
            DirectoryFailureClass.AccountState =>
                disclosureMode == ErrorDisclosureMode.Informative
                    ? PolicyViolation(AccountStateMessage, ApiErrorCode.ChangeNotPermitted, innerException)
                    : InvalidCredentials(innerException),
            DirectoryFailureClass.NewPasswordPolicy =>
                PolicyViolation(NewPasswordPolicyMessage, ApiErrorCode.ComplexPassword, innerException),
            DirectoryFailureClass.ChangeNotPermitted =>
                PolicyViolation(ChangeNotPermittedMessage, ApiErrorCode.ChangeNotPermitted, innerException),
            _ =>
                innerException is null
                    ? new DirectoryUnavailableException(DirectoryFailureMessage)
                    : new DirectoryUnavailableException(DirectoryFailureMessage, innerException),
        };
    }

    /// <summary>
    /// Builds the exception for the structural "user could not be resolved"
    /// condition (an empty search result or a null principal, where no Win32
    /// code exists). Kept here so both providers report unknown users through
    /// the same posture-aware routing as the coded existence failures:
    /// hardened → indistinguishable from a wrong password; informative →
    /// <see cref="UserNotFoundException"/>.
    /// </summary>
    /// <param name="disclosureMode">The configured disclosure posture.</param>
    /// <param name="innerException">Optional transport exception, preserved for logs.</param>
    /// <returns>The domain exception to throw.</returns>
    public static Exception CreateUserNotFoundError(
        ErrorDisclosureMode disclosureMode,
        Exception? innerException = null)
    {
        if (disclosureMode == ErrorDisclosureMode.Informative)
        {
            return innerException is null
                ? new UserNotFoundException(UserNotFoundMessage)
                : new UserNotFoundException(UserNotFoundMessage, innerException);
        }

        return InvalidCredentials(innerException);
    }

    /// <summary>
    /// Translates an arbitrary exception raised by a directory operation:
    /// extracts a Win32 code from the exception chain when one is present and
    /// routes it through <see cref="Translate(int, ErrorDisclosureMode, Exception?)"/>;
    /// anything unrecognizable becomes a <see cref="DirectoryUnavailableException"/>
    /// with the curated <see cref="DirectoryFailureMessage"/>. The original
    /// exception is preserved as the inner exception so its detail reaches
    /// logs, never the wire.
    /// </summary>
    /// <param name="exception">The exception raised by the directory operation.</param>
    /// <param name="disclosureMode">The configured disclosure posture.</param>
    /// <returns>The domain exception to throw.</returns>
    public static Exception TranslateException(Exception exception, ErrorDisclosureMode disclosureMode) =>
        TranslateException(exception, disclosureMode, out _);

    /// <summary>
    /// Same as <see cref="TranslateException(Exception, ErrorDisclosureMode)"/>
    /// but also reports the originating <see cref="DirectoryFailureClass"/>, so
    /// callers that need to make decisions about the failure (e.g. the
    /// administrative-reset gate) can act on the class rather than the
    /// exception shape — several classes intentionally share an exception type
    /// and code on the wire.
    /// </summary>
    /// <param name="exception">The exception raised by the directory operation.</param>
    /// <param name="disclosureMode">The configured disclosure posture.</param>
    /// <param name="failureClass">The classification of the failure;
    /// <see cref="DirectoryFailureClass.Infrastructure"/> when no Win32 code
    /// could be recovered.</param>
    /// <returns>The domain exception to throw.</returns>
    public static Exception TranslateException(
        Exception exception,
        ErrorDisclosureMode disclosureMode,
        out DirectoryFailureClass failureClass)
    {
        ArgumentNullException.ThrowIfNull(exception);

        if (TryGetWin32Code(exception, out var code))
        {
            failureClass = Classify(code);
            return Translate(code, disclosureMode, exception);
        }

        failureClass = DirectoryFailureClass.Infrastructure;
        return new DirectoryUnavailableException(DirectoryFailureMessage, exception);
    }

    /// <summary>
    /// Builds the curated exception for the "this account cannot change its
    /// own password" condition, for providers that detect the flag directly
    /// (AD's <c>UserCannotChangePassword</c>, the LDAP security-descriptor
    /// check) rather than receiving it as an error code. Identical in both
    /// disclosure modes: the condition is only ever raised after the caller
    /// proved the current password.
    /// </summary>
    /// <param name="innerException">Optional transport exception, preserved for logs.</param>
    /// <returns>The domain exception to throw.</returns>
    public static Exception CreateChangeNotPermittedError(Exception? innerException = null) =>
        PolicyViolation(ChangeNotPermittedMessage, ApiErrorCode.ChangeNotPermitted, innerException);

    private static InvalidCredentialsException InvalidCredentials(Exception? innerException) =>
        innerException is null
            ? new InvalidCredentialsException(InvalidCredentialsMessage)
            : new InvalidCredentialsException(InvalidCredentialsMessage, innerException);

    private static PasswordPolicyViolationException PolicyViolation(
        string message, ApiErrorCode errorCode, Exception? innerException) =>
        innerException is null
            ? new PasswordPolicyViolationException(message, errorCode)
            : new PasswordPolicyViolationException(message, errorCode, innerException);

    /// <summary>
    /// Walks an exception chain looking for a Win32 error code: a
    /// <see cref="Win32Exception.NativeErrorCode"/>, or an HRESULT in the
    /// FACILITY_WIN32 range (0x8007xxxx, e.g. COMException 0x800708C5 →
    /// 0x8C5/NERR_PasswordTooShort) whose low word is the code. Outermost
    /// match wins; COR HRESULTs (facility 0x13) are skipped so wrapped
    /// directory exceptions still surface their inner COM code.
    /// </summary>
    /// <param name="exception">The head of the exception chain.</param>
    /// <param name="win32Code">The extracted Win32 code.</param>
    /// <returns><see langword="true"/> when a code was found.</returns>
    public static bool TryGetWin32Code(Exception? exception, out int win32Code)
    {
        const int facilityWin32Mask = unchecked((int)0xFFFF0000);
        const int facilityWin32Error = unchecked((int)0x80070000);

        for (var ex = exception; ex != null; ex = ex.InnerException)
        {
            if (ex is Win32Exception win32Exception)
            {
                win32Code = win32Exception.NativeErrorCode;
                return true;
            }

            if ((ex.HResult & facilityWin32Mask) == facilityWin32Error)
            {
                win32Code = ex.HResult & 0xFFFF;
                return true;
            }
        }

        win32Code = 0;
        return false;
    }
}
