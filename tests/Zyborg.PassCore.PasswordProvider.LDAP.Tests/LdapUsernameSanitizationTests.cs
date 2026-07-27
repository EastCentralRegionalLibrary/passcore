using Unosquare.PassCore.Common.Exceptions;

namespace Zyborg.PassCore.PasswordProvider.LDAP.Tests;

public class LdapUsernameSanitizationTests
{
    [Theory]
    [InlineData("jdoe", "jdoe", null)]
    [InlineData("j.doe", "j.doe", null)]
    [InlineData("jdoe@example.com", "jdoe@example.com", "example.com")]
    [InlineData("j-doe_2@example.com", "j-doe_2@example.com", "example.com")]
    [InlineData("jdoe", "jdoe@example.com", "example.com")]
    [InlineData("EXAMPLE\\jdoe", "jdoe@example.com", "example.com")]
    public void SanitizeUsername_ValidInput_ReturnsExpected(string input, string expected, string? defaultDomain)
    {
        Assert.Equal(expected, LdapPasswordChangeProvider.SanitizeUsername(input, defaultDomain));
    }

    [Theory]
    [InlineData("jdoe@wrongdomain.com", "example.com")]
    [InlineData("WRONGDOMAIN\\jdoe", "example.com")]
    [InlineData("jdoe@example.com", null)]
    [InlineData("EXAMPLE\\jdoe", null)]
    public void SanitizeUsername_InvalidDomain_Throws(string input, string? defaultDomain)
    {
        Assert.Throws<InvalidCredentialsException>(
            () => LdapPasswordChangeProvider.SanitizeUsername(input, defaultDomain));
    }

    [Theory]
    [InlineData("jd*e")]
    [InlineData(@"jd\e")]
    [InlineData("jd=e")]
    [InlineData("jd,e")]
    [InlineData("jd;e")]
    [InlineData("jd|e")]
    [InlineData("jd<e>")]
    public void SanitizeUsername_InvalidAccountNameCharacters_Throws(string input)
    {
        Assert.Throws<InvalidCredentialsException>(
            () => LdapPasswordChangeProvider.SanitizeUsername(input));
    }

    [Theory]
    [InlineData("jd\0e")]
    [InlineData("jd\ne")]
    [InlineData("jd\te")]
    public void SanitizeUsername_ControlCharacters_Throws(string input)
    {
        Assert.Throws<InvalidCredentialsException>(
            () => LdapPasswordChangeProvider.SanitizeUsername(input));
    }

    [Fact]
    public void SanitizeUsername_EmptyLocalPart_Throws()
    {
        Assert.Throws<InvalidCredentialsException>(
            () => LdapPasswordChangeProvider.SanitizeUsername("@example.com"));
    }

    [Theory]
    [InlineData("jd(e", "jd\\28e")]
    [InlineData("jd)e", "jd\\29e")]
    [InlineData("j(d)e", "j\\28d\\29e")]
    public void SanitizeUsername_FilterMetacharacters_AreEscaped(string input, string expected)
    {
        Assert.Equal(expected, LdapPasswordChangeProvider.SanitizeUsername(input));
    }

    [Theory]
    [InlineData("admin)(objectClass=person")]
    [InlineData("*)(sAMAccountName=*")]
    [InlineData("x)(|(cn=a)(cn=b)")]
    [InlineData("jd(e")]
    [InlineData("jd)e")]
    [InlineData("plainuser")]
    public void SanitizeUsername_OutputCannotAlterFilterStructure(string input)
    {
        string value;
        try
        {
            value = LdapPasswordChangeProvider.SanitizeUsername(input);
        }
        catch (InvalidCredentialsException)
        {
            return; // Rejected outright is also structure-safe
        }

        // After substitution into "(attr={Username})" the value must contain no
        // unescaped RFC 4515 metacharacters: every '\' introduces a two-hex-digit
        // escape, and '(', ')', '*', NUL never appear raw.
        for (var i = 0; i < value.Length; i++)
        {
            var c = value[i];
            Assert.True(c is not ('(' or ')' or '*' or '\0'),
                $"Unescaped metacharacter '{c}' at index {i} in \"{value}\"");

            if (c == '\\')
            {
                Assert.True(i + 2 < value.Length
                    && Uri.IsHexDigit(value[i + 1])
                    && Uri.IsHexDigit(value[i + 2]),
                    $"Backslash at index {i} in \"{value}\" is not a valid \\XX escape");
                i += 2;
            }
        }
    }

    [Theory]
    [InlineData("a*b", "a\\2ab")]
    [InlineData("a\\b", "a\\5cb")]
    [InlineData("a(b)c", "a\\28b\\29c")]
    [InlineData("a\0b", "a\\00b")]
    [InlineData("plain", "plain")]
    public void EscapeLdapSearchFilterValue_EscapesRfc4515Metacharacters(string input, string expected)
    {
        Assert.Equal(expected, LdapPasswordChangeProvider.EscapeLdapSearchFilterValue(input));
    }
}
