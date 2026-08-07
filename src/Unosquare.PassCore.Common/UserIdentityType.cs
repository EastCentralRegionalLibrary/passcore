namespace Unosquare.PassCore.Common;

/// <summary>
/// The identity types the AD provider can resolve a user by, mirroring
/// <c>System.DirectoryServices.AccountManagement.IdentityType</c> without depending on
/// it. <c>IdentityType</c> lives in a Windows-only assembly, so a Common-owned copy is
/// what lets the classification logic below be exercised cross-platform.
/// </summary>
public enum UserIdentityType
{
    /// <summary>The user's distinguished name.</summary>
    DistinguishedName,

    /// <summary>The user's GUID.</summary>
    Guid,

    /// <summary>The user's name.</summary>
    Name,

    /// <summary>The user's SAM account name.</summary>
    SamAccountName,

    /// <summary>The user's security identifier.</summary>
    Sid,

    /// <summary>The user's user principal name.</summary>
    UserPrincipalName,
}

/// <summary>
/// Classifies the configured <c>IdTypeForUser</c> string into a <see cref="UserIdentityType"/>.
/// </summary>
/// <remarks>
/// Moved verbatim out of the AD provider's <c>SetIdType</c>: same aliases, same
/// <c>Trim().ToLowerInvariant()</c> normalization, same <see cref="UserIdentityType.UserPrincipalName"/>
/// fallback. <c>IdentityType</c> is Windows-only, so nothing that returned it could be
/// tested cross-platform; this classifier can be.
/// </remarks>
public static class UserIdentityTypeClassifier
{
    /// <summary>
    /// Resolves a raw <c>IdTypeForUser</c> configuration value to a <see cref="UserIdentityType"/>.
    /// </summary>
    /// <param name="idTypeForUser">
    /// The raw configuration value. Absent, null, or blank is a legitimate request for
    /// the default and resolves to <see cref="UserIdentityType.UserPrincipalName"/> with
    /// <paramref name="recognized"/> set to <see langword="true"/> — it is a legitimate
    /// default, distinguishable from a non-blank value that failed to match any alias.
    /// </param>
    /// <param name="recognized">
    /// <see langword="true"/> when <paramref name="idTypeForUser"/> was absent, null, or
    /// blank (the legitimate default) or matched one of the known aliases;
    /// <see langword="false"/> when it was present, non-blank, and did not match any
    /// alias.
    /// </param>
    /// <param name="usableInWebInterface">
    /// <see langword="true"/> when the resolved <see cref="UserIdentityType"/> can be
    /// accepted from the web interface. <see cref="UserIdentityType.DistinguishedName"/>,
    /// <see cref="UserIdentityType.Guid"/>, and <see cref="UserIdentityType.Sid"/> are not
    /// usable; every other member is.
    /// </param>
    /// <returns>The resolved <see cref="UserIdentityType"/>.</returns>
    public static UserIdentityType Classify(string? idTypeForUser, out bool recognized, out bool usableInWebInterface)
    {
        var normalized = idTypeForUser?.Trim().ToLowerInvariant();
        var isBlank = string.IsNullOrWhiteSpace(normalized);

        var matchedAlias = true;
        var resolved = normalized switch // Use switch expression for concise mapping
        {
            "distinguishedname" or "distinguished name" or "dn" => UserIdentityType.DistinguishedName,
            "globally unique identifier" or "globallyuniqueidentifier" or "guid" => UserIdentityType.Guid,
            "name" or "nm" => UserIdentityType.Name,
            "samaccountname" or "accountname" or "sam account" or "sam account name" or "sam" => UserIdentityType.SamAccountName,
            "securityidentifier" or "securityid" or "secid" or "security identifier" or "sid" => UserIdentityType.Sid,
            // Not present in the switch this table was moved from, where UserPrincipalName
            // was reachable only through the fallback arm. That was harmless while the
            // fallback was silent, but it is not once an unmatched value warns: the shipped
            // appsettings.json sets "IdTypeForUser": "UPN", so every default deployment
            // would be told its own documented value is unrecognized. Resolution is
            // unchanged -- these spellings already resolved to UserPrincipalName via the
            // fallback -- this only distinguishes them from a genuine typo.
            "userprincipalname" or "user principal name" or "upn" => UserIdentityType.UserPrincipalName,
            _ => Unmatched(out matchedAlias) // Default to UserPrincipalName if no match or invalid input
        };

        recognized = isBlank || matchedAlias;
        usableInWebInterface = resolved is not (UserIdentityType.DistinguishedName or UserIdentityType.Guid or UserIdentityType.Sid);

        return resolved;
    }

    private static UserIdentityType Unmatched(out bool matchedAlias)
    {
        matchedAlias = false;
        return UserIdentityType.UserPrincipalName;
    }
}
