using Microsoft.Win32.SafeHandles;
namespace Unosquare.PassCore.PasswordProvider;

/// <summary>
/// This code is taken from the answer https://stackoverflow.com/a/1766203
/// from https://stackoverflow.com/questions/1394025/active-directory-ldap-check-account-locked-out-password-expired.
/// </summary>
public class NativeMethods
{
    // The expired/must-change LogonUser error codes (1330/1907) previously kept
    // here now come from the shared Win32ErrorCode catalog via
    // DirectoryErrorTranslator.IsPasswordExpiredOrMustChange.

    // here are enums
    internal enum LogonTypes : uint
    {
        /// <summary>
        /// The interactive
        /// </summary>
        Interactive = 2,

        /// <summary>
        /// The network
        /// </summary>
        Network = 3,

        /// <summary>
        /// The service
        /// </summary>
        Service = 5,
    }

    internal enum LogonProviders : uint
    {
        /// <summary>
        /// The default for platform (use this!)
        /// </summary>
        Default = 0,
    }

    [System.Runtime.InteropServices.DllImport("advapi32.dll", SetLastError = true, CharSet = System.Runtime.InteropServices.CharSet.Unicode)]
    internal static extern bool LogonUser(
        string principal,
        string authority,
        string password,
        LogonTypes logonType,
        LogonProviders logonProvider,
        out SafeAccessTokenHandle token);
}