namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// <see cref="UserIdentityTypeClassifier"/> moved the AD provider's <c>SetIdType</c>
/// alias table verbatim into Common. <c>IdentityType</c>
/// (<c>System.DirectoryServices.AccountManagement</c>) is Windows-only, so nothing that
/// returned it could be exercised cross-platform; this classifier can be.
/// </summary>
public class UserIdentityTypeTests
{
    [Theory]
    [InlineData("distinguishedname", UserIdentityType.DistinguishedName)]
    [InlineData("distinguished name", UserIdentityType.DistinguishedName)]
    [InlineData("dn", UserIdentityType.DistinguishedName)]
    [InlineData("globally unique identifier", UserIdentityType.Guid)]
    [InlineData("globallyuniqueidentifier", UserIdentityType.Guid)]
    [InlineData("guid", UserIdentityType.Guid)]
    [InlineData("name", UserIdentityType.Name)]
    [InlineData("nm", UserIdentityType.Name)]
    [InlineData("samaccountname", UserIdentityType.SamAccountName)]
    [InlineData("accountname", UserIdentityType.SamAccountName)]
    [InlineData("sam account", UserIdentityType.SamAccountName)]
    [InlineData("sam account name", UserIdentityType.SamAccountName)]
    [InlineData("sam", UserIdentityType.SamAccountName)]
    [InlineData("securityidentifier", UserIdentityType.Sid)]
    [InlineData("securityid", UserIdentityType.Sid)]
    [InlineData("secid", UserIdentityType.Sid)]
    [InlineData("security identifier", UserIdentityType.Sid)]
    [InlineData("sid", UserIdentityType.Sid)]
    public void EveryAlias_ResolvesToTheSameTypeItResolvesToToday(string alias, UserIdentityType expected)
    {
        var resolved = UserIdentityTypeClassifier.Classify(alias, out var recognized, out _);

        Assert.Equal(expected, resolved);
        Assert.True(recognized);
    }

    /// <summary>
    /// Aliases are matched case-insensitively and with surrounding whitespace
    /// trimmed, exactly as <c>Trim().ToLowerInvariant()</c> does in the provider this
    /// table was moved from.
    /// </summary>
    [Theory]
    [InlineData("  SamAccountName  ", UserIdentityType.SamAccountName)]
    [InlineData("SID", UserIdentityType.Sid)]
    [InlineData("Distinguished Name", UserIdentityType.DistinguishedName)]
    public void Aliases_AreNormalizedBeforeMatching(string alias, UserIdentityType expected)
    {
        var resolved = UserIdentityTypeClassifier.Classify(alias, out var recognized, out _);

        Assert.Equal(expected, resolved);
        Assert.True(recognized);
    }

    /// <summary>
    /// Absent, null, and blank input is the legitimate request for the default —
    /// distinguishable from an unrecognized value only by <c>recognized</c>, not by the
    /// resolved type, since both resolve to UserPrincipalName.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void AbsentNullOrBlankInput_ResolvesToUserPrincipalNameAndIsRecognized(string? idTypeForUser)
    {
        var resolved = UserIdentityTypeClassifier.Classify(idTypeForUser, out var recognized, out var usable);

        Assert.Equal(UserIdentityType.UserPrincipalName, resolved);
        Assert.True(recognized);
        Assert.True(usable);
    }

    /// <summary>
    /// An unrecognized non-blank value falls through to the same default as a blank
    /// value, but must be distinguishable from it: this is the case
    /// <c>recognized = false</c> exists for.
    /// </summary>
    [Fact]
    public void UnrecognizedNonBlankValue_ResolvesToUserPrincipalNameAndIsNotRecognized()
    {
        var resolved = UserIdentityTypeClassifier.Classify("not-a-real-alias", out var recognized, out var usable);

        Assert.Equal(UserIdentityType.UserPrincipalName, resolved);
        Assert.False(recognized);
        Assert.True(usable);
    }

    /// <summary>
    /// Blank input and an unrecognized value both resolve to UserPrincipalName, so the
    /// only place they differ is <c>recognized</c> — assert that explicitly rather than
    /// relying on the resolved type alone.
    /// </summary>
    [Fact]
    public void BlankInput_IsDistinguishableFromAnUnrecognizedValue()
    {
        var blankResolved = UserIdentityTypeClassifier.Classify(null, out var blankRecognized, out _);
        var unrecognizedResolved = UserIdentityTypeClassifier.Classify("bogus", out var unrecognizedRecognized, out _);

        Assert.Equal(blankResolved, unrecognizedResolved);
        Assert.True(blankRecognized);
        Assert.False(unrecognizedRecognized);
    }

    [Theory]
    [InlineData(UserIdentityType.DistinguishedName)]
    [InlineData(UserIdentityType.Guid)]
    [InlineData(UserIdentityType.Sid)]
    public void SomeTypes_AreNotUsableInTheWebInterface(UserIdentityType type)
    {
        var alias = type switch
        {
            UserIdentityType.DistinguishedName => "dn",
            UserIdentityType.Guid => "guid",
            UserIdentityType.Sid => "sid",
            _ => throw new InvalidOperationException("Unexpected type for this theory."),
        };

        UserIdentityTypeClassifier.Classify(alias, out _, out var usable);

        Assert.False(usable);
    }

    [Theory]
    [InlineData(UserIdentityType.SamAccountName)]
    [InlineData(UserIdentityType.UserPrincipalName)]
    [InlineData(UserIdentityType.Name)]
    public void OtherTypes_AreUsableInTheWebInterface(UserIdentityType type)
    {
        var alias = type switch
        {
            UserIdentityType.SamAccountName => "sam",
            UserIdentityType.UserPrincipalName => null,
            UserIdentityType.Name => "name",
            _ => throw new InvalidOperationException("Unexpected type for this theory."),
        };

        UserIdentityTypeClassifier.Classify(alias, out _, out var usable);

        Assert.True(usable);
    }
}
