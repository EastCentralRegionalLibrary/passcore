namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

public class Rfc4514DnMatchingTests
{
    [Theory]
    // 1. Exact full-DN match, and case-insensitivity of it
    [InlineData("CN=Admins,OU=Groups,DC=example,DC=com", "CN=Admins,OU=Groups,DC=example,DC=com", true)]
    [InlineData("CN=Admins,OU=Groups,DC=example,DC=com", "cn=admins,ou=groups,dc=example,dc=com", true)]
    [InlineData("CN=Admins,OU=Groups,DC=example,DC=com", "CN=Admins,OU=Groups,DC=example,DC=org", false)]

    // 2. Plain first-RDN match, and case-insensitivity of it
    [InlineData("CN=Admins,OU=Groups,DC=example,DC=com", "Admins", true)]
    [InlineData("CN=Admins,OU=Groups,DC=example,DC=com", "admins", true)]
    [InlineData("cn=Admins,ou=groups,dc=example,dc=com", "Admins", true)]
    [InlineData("cn=Admins,ou=groups,dc=example,dc=com", "admins", true)]

    // 3. A literal comma inside the CN escaped as `\,` matching raw `Comma`
    [InlineData(@"CN=Admins\, Senior,OU=Groups,DC=example,DC=com", "Admins, Senior", true)]
    [InlineData(@"CN=Admins\, Senior,OU=Groups,DC=example,DC=com", "admins, senior", true)]
    [InlineData(@"CN=Admins\, Senior,OU=Groups,DC=example,DC=com", "Admins", false)]
    [InlineData(@"CN=Admins\, Senior,OU=Groups,DC=example,DC=com", "Senior", false)]

    // 4. An escaped backslash in the CN (`\\`)
    [InlineData(@"CN=Admins\\Senior,OU=Groups,DC=example,DC=com", @"Admins\Senior", true)]
    [InlineData(@"CN=Admins\\Senior,OU=Groups,DC=example,DC=com", @"admins\senior", true)]
    [InlineData(@"CN=Admins\\Senior,OU=Groups,DC=example,DC=com", "Admins\\\\Senior", false)]

    // 5. Leading/trailing whitespace around the RDN value
    [InlineData("CN= Admins ,OU=Groups,DC=example,DC=com", "Admins", true)]
    [InlineData("CN=  Admins  ,OU=Groups,DC=example,DC=com", "Admins", true)]
    [InlineData("CN=\tAdmins\t,OU=Groups,DC=example,DC=com", "Admins", true)]
    [InlineData("CN=Admins,OU=Groups,DC=example,DC=com", " Admins ", false)] // Trim only applies to DN RDN value, not the target groupName

    // 6. An RDN with no `=` at all (must not match)
    [InlineData("CNAdmins,OU=Groups,DC=example,DC=com", "Admins", false)]
    [InlineData("Admins", "Admins", true)] // Matches because of exact full-DN match: string.Equals(dn, groupName, OrdinalIgnoreCase)
    [InlineData("Admins,OU=Groups", "Admins", false)] // No '=' in the first RDN part

    // 7. An empty `dn` and an empty `groupName`
    [InlineData("", "", true)] // Matches via exact full-DN match string.Equals("", "")
    [InlineData("CN=Admins", "", false)]
    [InlineData("", "Admins", false)]

    // 8. A DN whose CN merely contains the group name as a substring (must not match)
    [InlineData("CN=AdminsExtra,OU=Groups,DC=example,DC=com", "Admins", false)]
    [InlineData("CN=ExtraAdmins,OU=Groups,DC=example,DC=com", "Admins", false)]
    [InlineData("CN=Admins,OU=Groups,DC=example,DC=com", "Admin", false)]
    public void DnMatchesGroup_Scenarios_ReturnExpected(string dn, string groupName, bool expected)
    {
        Assert.Equal(expected, LdapPasswordChangeProvider.DnMatchesGroup(dn, groupName));
    }

    /// <summary>
    /// RFC 4514 permits hex escapes, so a comma may arrive as '\2C' rather than '\,'.
    /// LdapPasswordChangeProvider.UnescapeRdnValue currently only handles the backslash-character form:
    /// it skips the backslash and appends the next single character, which turns '\2C' into '2C' instead of ','.
    /// This test pins this CURRENT behaviour and is marked as pinned-not-endorsed.
    /// </summary>
    [Fact]
    public void DnMatchesGroup_HexEscapedComma_PinnedNotEndorsed_ReturnsFalse()
    {
        // Pinned-not-endorsed behavior:
        // A hex-escaped comma (e.g. \2C) is not correctly unescaped to ',' by UnescapeRdnValue.
        // It skips '\' and keeps '2', resulting in "Admins2C Senior" (with the 'C' remaining in the stream).
        // Let's assert that the current implementation turns CN=Admins\2C Senior into "Admins2C Senior",
        // and therefore does NOT match "Admins, Senior".
        var dnWithHexEscapedComma = @"CN=Admins\2C Senior,OU=Groups,DC=example,DC=com";

        // Current behavior turns CN part into "Admins2C Senior".
        Assert.True(LdapPasswordChangeProvider.DnMatchesGroup(dnWithHexEscapedComma, "Admins2C Senior"));
        Assert.False(LdapPasswordChangeProvider.DnMatchesGroup(dnWithHexEscapedComma, "Admins, Senior"));
    }
}
