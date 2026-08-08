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
    /// Verified that LdapPasswordChangeProvider.UnescapeRdnValue correctly handles hex escapes.
    /// </summary>
    [Fact]
    public void DnMatchesGroup_HexEscapedComma_Corrected_ReturnsTrue()
    {
        var dnWithHexEscapedComma = @"CN=Admins\2C Senior,OU=Groups,DC=example,DC=com";

        Assert.False(LdapPasswordChangeProvider.DnMatchesGroup(dnWithHexEscapedComma, "Admins2C Senior"));
        Assert.True(LdapPasswordChangeProvider.DnMatchesGroup(dnWithHexEscapedComma, "Admins, Senior"));
    }

    [Theory]
    // Hex escape cases
    [InlineData(@"CN=Admins\2C Senior,OU=Groups,DC=example,DC=com", "Admins, Senior", true)]
    [InlineData(@"CN=Admins\5C Senior,OU=Groups,DC=example,DC=com", @"Admins\ Senior", true)]
    [InlineData(@"CN=Admins\2c Senior,OU=Groups,DC=example,DC=com", "Admins, Senior", true)]
    // Consecutive hex escapes (UTF-8 multi-byte sequence \C3\A9 -> é)
    [InlineData(@"CN=Caf\C3\A9,OU=Groups,DC=example,DC=com", "Café", true)]
    // Hex escape adjacent to a literal escape (e.g., \2C adjacent to \, or adjacent to literal space or space-escape)
    [InlineData(@"CN=Admins\2C\, Senior,OU=Groups,DC=example,DC=com", "Admins,, Senior", true)]
    // Trailing lone backslash at the end of string (does not read past, does not throw, handled gracefully)
    [InlineData(@"CN=Admins\,OU=Groups,DC=example,DC=com", "Admins", false)]
    [InlineData(@"CN=Admins\", "Admins", false)]
    [InlineData(@"CN=Admins\", @"Admins\", true)]
    public void DnMatchesGroup_HexAndEdgeScenarios_ReturnExpected(string dn, string groupName, bool expected)
    {
        Assert.Equal(expected, LdapPasswordChangeProvider.DnMatchesGroup(dn, groupName));
    }
}
