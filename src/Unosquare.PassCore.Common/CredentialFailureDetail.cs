using System;
using System.ComponentModel;
using System.Globalization;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Builds the diagnostic inner exception that accompanies a failed
/// credential verification.
/// <para>
/// <see cref="ErrorDisclosureMode.Hardened"/> — the default — deliberately
/// collapses wrong-password, unknown-user, and locked/disabled/restricted
/// account conditions into one indistinguishable
/// <see cref="Exceptions.InvalidCredentialsException"/> so that no account
/// oracle survives on the wire. That is the intended posture, and it leaves
/// the server log as the only place the real condition can still be read.
/// Attaching the result of this factory as the verification failure's inner
/// exception is what keeps that compensating control working: the provider's
/// existing failure log (EventId 4) records the chain, so an operator holding
/// a correlation ID can tell a mistyped password from a lockout while the
/// caller still learns nothing.
/// </para>
/// <para>
/// The detail is <b>log-only by construction</b>. <see cref="ApiErrorMapper"/>
/// reads <see cref="Exception.Message"/> of the thrown exception and never
/// walks <see cref="Exception.InnerException"/>, so nothing produced here can
/// reach <see cref="ApiErrorItem.Message"/> or any other wire field in either
/// disclosure mode.
/// </para>
/// </summary>
public static class CredentialFailureDetail
{
    /// <summary>
    /// Creates a <see cref="Win32Exception"/> describing a credential-verification
    /// failure, or <see langword="null"/> when there is no code to describe.
    /// <para>
    /// The code is carried in <see cref="Win32Exception.NativeErrorCode"/>, so
    /// <see cref="DirectoryErrorTranslator.TryGetWin32Code"/> recovers it from
    /// the chain exactly as it does for the LDAP provider's transport
    /// exceptions. Cataloged codes additionally get the symbolic name and the
    /// curated <see cref="Win32ErrorCode.Description"/> as the message —
    /// deterministic across platforms and locales, unlike the OS-supplied text
    /// that an uncataloged code falls back to.
    /// </para>
    /// </summary>
    /// <param name="win32Code">The Win32 code reported by the failed
    /// verification. Zero means "no code was reported" and yields
    /// <see langword="null"/>, leaving the failure exactly as detail-free as it
    /// was before.</param>
    /// <returns>The diagnostic exception, or <see langword="null"/>.</returns>
    public static Exception? ForWin32Code(int win32Code)
    {
        if (win32Code == 0)
            return null;

        var cataloged = Win32ErrorCode.ByCode(win32Code);

        return cataloged == null
            ? new Win32Exception(win32Code)
            : new Win32Exception(
                win32Code,
                string.Format(
                    CultureInfo.InvariantCulture,
                    "{0} (0x{1:X}): {2}",
                    cataloged.CodeName,
                    win32Code,
                    cataloged.Description));
    }
}
