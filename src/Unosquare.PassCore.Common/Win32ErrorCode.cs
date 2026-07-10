using System.Collections.Generic;

namespace Unosquare.PassCore.Common;

/// <summary>
/// Catalog of the Win32 error codes Active Directory surfaces during password
/// change operations, each annotated with the <see cref="DirectoryFailureClass"/>
/// that drives <see cref="DirectoryErrorTranslator"/> routing. This is AD/Win32
/// semantics shared by every provider, independent of the transport (LDAP wire
/// messages, COM HRESULTs, or LogonUser last-error codes) used to obtain the code.
/// </summary>
public sealed class Win32ErrorCode
{
    /// <summary>
    /// Codes anticipated from a password change request. Win32 codes are from
    /// <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/18d8fbe8-a967-4f1c-ae50-99ca8e491d2d">MS-ERREF</a>;
    /// the NERR_* password codes (0x8C3–0x8C6) are the lmerr.h codes that
    /// Active Directory change/set-password APIs report through COM HRESULTs
    /// (e.g. 0x800708C5).
    /// </summary>
    public static readonly IEnumerable<Win32ErrorCode> Codes =
    [
        new(0x00000005, "ERROR_ACCESS_DENIED",
            "Access is denied.",
            DirectoryFailureClass.Infrastructure),
        new(0x00000056, "ERROR_INVALID_PASSWORD",
            "The specified network password is not correct.",
            DirectoryFailureClass.Credentials),
        new(0x00000523, "ERROR_INVALID_ACCOUNT_NAME",
            "The name provided is not a properly formed account name.",
            DirectoryFailureClass.Existence),
        new(0x00000524, "ERROR_USER_EXISTS",
            "The specified account already exists.",
            DirectoryFailureClass.Infrastructure),
        new(0x00000525, "ERROR_NO_SUCH_USER",
            "The specified account does not exist.",
            DirectoryFailureClass.Existence),
        new(0x0000052B, "ERROR_WRONG_PASSWORD",
            "Unable to update the password. The value provided as the current password is incorrect.",
            DirectoryFailureClass.Credentials),
        new(0x0000052C, "ERROR_ILL_FORMED_PASSWORD",
            "Unable to update the password. The value provided for the new password contains values that are not allowed in passwords.",
            DirectoryFailureClass.NewPasswordPolicy),
        new(0x0000052D, "ERROR_PASSWORD_RESTRICTION",
            "Unable to update the password. The value provided for the new password does not meet the length, complexity, or history requirements of the domain.",
            DirectoryFailureClass.NewPasswordPolicy),
        new(0x0000052E, "ERROR_LOGON_FAILURE",
            "Logon failure: Unknown user name or bad password.",
            DirectoryFailureClass.Credentials),
        new(0x0000052F, "ERROR_ACCOUNT_RESTRICTION",
            "Logon failure: User account restriction. Possible reasons are blank passwords not allowed, logon hour restrictions, or a policy restriction has been enforced.",
            DirectoryFailureClass.AccountState),
        new(0x00000530, "ERROR_INVALID_LOGON_HOURS",
            "Logon failure: Account logon time restriction violation.",
            DirectoryFailureClass.AccountState),
        new(0x00000531, "ERROR_INVALID_WORKSTATION",
            "Logon failure: User not allowed to log on to this computer.",
            DirectoryFailureClass.AccountState),
        new(0x00000532, "ERROR_PASSWORD_EXPIRED",
            "Logon failure: The specified account password has expired.",
            DirectoryFailureClass.PasswordExpiredOrMustChange),
        new(0x00000533, "ERROR_ACCOUNT_DISABLED",
            "Logon failure: Account currently disabled.",
            DirectoryFailureClass.AccountState),
        new(0x00000701, "ERROR_ACCOUNT_EXPIRED",
            "The user's account has expired.",
            DirectoryFailureClass.AccountState),
        new(0x00000773, "ERROR_PASSWORD_MUST_CHANGE",
            "The user's password must be changed before logging on the first time.",
            DirectoryFailureClass.PasswordExpiredOrMustChange),
        new(0x00000774, "ERROR_DOMAIN_CONTROLLER_NOT_FOUND",
            "Could not find the domain controller for this domain.",
            DirectoryFailureClass.Infrastructure),
        new(0x00000775, "ERROR_ACCOUNT_LOCKED_OUT",
            "The referenced account is currently locked out and cannot be logged on to.",
            DirectoryFailureClass.AccountState),
        new(0x000008C3, "NERR_PasswordCantChange",
            "The password of this user cannot change.",
            DirectoryFailureClass.ChangeNotPermitted),
        new(0x000008C4, "NERR_PasswordHistConflict",
            "This password cannot be used now.",
            DirectoryFailureClass.NewPasswordPolicy),
        new(0x000008C5, "NERR_PasswordTooShort",
            "The password does not meet the password policy requirements. Check the minimum password length, password complexity and password history requirements.",
            DirectoryFailureClass.NewPasswordPolicy),
        new(0x000008C6, "NERR_PasswordTooRecent",
            "The password of this user is too recent to change.",
            DirectoryFailureClass.NewPasswordPolicy),
    ];

    private static readonly Dictionary<int, Win32ErrorCode> ErrorByCode = [];

    static Win32ErrorCode()
    {
        foreach (var c in Codes)
        {
            ErrorByCode[c.Code] = c;
        }
    }

    private Win32ErrorCode(int code, string codeName, string desc, DirectoryFailureClass failureClass)
    {
        Code = code;
        CodeName = codeName;
        Description = desc;
        FailureClass = failureClass;
    }

    /// <summary>
    /// Gets the numeric Win32 error code.
    /// </summary>
    public int Code { get; }

    /// <summary>
    /// Gets the symbolic name of the code.
    /// </summary>
    public string CodeName { get; }

    /// <summary>
    /// Gets the documented description. Curated catalog text safe for logs;
    /// never combined with raw exception text.
    /// </summary>
    public string Description { get; }

    /// <summary>
    /// Gets the failure classification that drives error routing.
    /// </summary>
    public DirectoryFailureClass FailureClass { get; }

    /// <summary>
    /// Gets the catalog entry for a code, or <see langword="null"/> if uncataloged.
    /// </summary>
    /// <param name="code">The Win32 error code.</param>
    /// <returns>The catalog entry, or <see langword="null"/>.</returns>
    public static Win32ErrorCode? ByCode(int code) =>
        ErrorByCode.TryGetValue(code, out var err) ? err : null;

    /// <summary>
    /// Returns a hash code for this instance.
    /// </summary>
    /// <returns>The numeric error code.</returns>
    public override int GetHashCode() => Code;

    /// <summary>
    /// Determines whether the specified object is a <see cref="Win32ErrorCode"/> with the same code.
    /// </summary>
    /// <param name="obj">The object to compare with this instance.</param>
    /// <returns><see langword="true"/> when the codes match.</returns>
    public override bool Equals(object? obj) =>
        obj is Win32ErrorCode err && Code == err.Code;
}
