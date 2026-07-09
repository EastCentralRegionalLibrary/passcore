namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

public class DnMatchesGroupTests
{
    [Theory]
    [InlineData("cn=Admins,ou=groups,dc=example,dc=com", "Admins")]
    [InlineData("CN=Admins,OU=groups,DC=example,DC=com", "admins")]
    [InlineData("cn=Admins,ou=groups,dc=example,dc=com", "cn=Admins,ou=groups,dc=example,dc=com")]
    [InlineData("CN=Admins,OU=groups,DC=example,DC=com", "cn=admins,ou=groups,dc=example,dc=com")]
    [InlineData("cn=Admins", "Admins")]
    public void DnMatchesGroup_MatchingRdnValueOrFullDn_ReturnsTrue(string dn, string groupName)
    {
        Assert.True(LdapPasswordChangeProvider.DnMatchesGroup(dn, groupName));
    }

    [Theory]
    [InlineData("cn=AdminsExtra,ou=groups,dc=example,dc=com", "Admins")]
    [InlineData("cn=Admins,ou=groups,dc=example,dc=com", "AdminsExtra")]
    [InlineData("cn=Admins,ou=groups,dc=example,dc=com", "groups")]
    [InlineData("not-a-dn", "Admins")]
    public void DnMatchesGroup_NonMatching_ReturnsFalse(string dn, string groupName)
    {
        Assert.False(LdapPasswordChangeProvider.DnMatchesGroup(dn, groupName));
    }

    [Fact]
    public void DnMatchesGroup_EscapedCommaInRdnValue_MatchesFullValue()
    {
        // AD escapes literal commas in memberOf DN values per RFC 4514.
        Assert.True(LdapPasswordChangeProvider.DnMatchesGroup(
            "CN=Smith\\, John,OU=groups,DC=example,DC=com",
            "Smith, John"));
    }

    [Fact]
    public void DnMatchesGroup_EscapedCommaInRdnValue_DoesNotMatchTruncatedValue()
    {
        Assert.False(LdapPasswordChangeProvider.DnMatchesGroup(
            "CN=Smith\\, John,OU=groups,DC=example,DC=com",
            "Smith"));
    }
}
