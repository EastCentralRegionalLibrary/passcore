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

    /// <summary>
    /// The complete qualifier-handling matrix, in one table, across both
    /// configuration states. The unconfigured rows are the ones that regressed:
    /// a qualified username used to be rejected outright when no
    /// <c>DefaultDomain</c> was set, which is precisely the input form the
    /// shipped UI asks for (<c>UseEmail: true</c>). "Accepted" here means the
    /// call returns a value; what that value is, is asserted alongside so the
    /// canonicalization rules are pinned too.
    /// </summary>
    [Theory]
    // No configured domain: nothing to validate a qualifier against, so every form is accepted.
    [InlineData("", "jdoe", "jdoe")]
    [InlineData("", "jdoe@example.com", "jdoe@example.com")]          // UPN suffix preserved
    [InlineData("", "jdoe@other.com", "jdoe@other.com")]              // ... whatever the suffix is
    [InlineData("", "EXAMPLE\\jdoe", "jdoe")]                         // NetBIOS name is not a UPN suffix; dropped
    [InlineData(null, "jdoe@example.com", "jdoe@example.com")]        // null is the same state as empty
    [InlineData(null, "EXAMPLE\\jdoe", "jdoe")]
    // Configured domain: authoritative, and every accepted form canonicalizes onto it.
    [InlineData("example.com", "jdoe", "jdoe@example.com")]
    [InlineData("example.com", "jdoe@example.com", "jdoe@example.com")]
    [InlineData("example.com", "EXAMPLE\\jdoe", "jdoe@example.com")]  // NetBIOS prefix match
    public void SanitizeUsername_QualifierMatrix_Accepted(
        string? defaultDomain, string input, string expected)
    {
        Assert.Equal(expected, LdapPasswordChangeProvider.SanitizeUsername(input, defaultDomain));
    }

    /// <summary>
    /// The one rejection row of the matrix: a qualifier that contradicts a
    /// configured <c>DefaultDomain</c>. A user of another domain must not be
    /// searched for as if they belonged to the configured one.
    /// </summary>
    [Theory]
    [InlineData("example.com", "jdoe@other.com")]
    [InlineData("example.com", "OTHER\\jdoe")]
    public void SanitizeUsername_QualifierMatrix_RejectedAgainstConfiguredDomain(
        string defaultDomain, string input)
    {
        Assert.Throws<InvalidCredentialsException>(
            () => LdapPasswordChangeProvider.SanitizeUsername(input, defaultDomain));
    }

    [Theory]
    [InlineData("jdoe@wrongdomain.com", "example.com")]
    [InlineData("WRONGDOMAIN\\jdoe", "example.com")]
    public void SanitizeUsername_InvalidDomain_Throws(string input, string? defaultDomain)
    {
        Assert.Throws<InvalidCredentialsException>(
            () => LdapPasswordChangeProvider.SanitizeUsername(input, defaultDomain));
    }

    /// <summary>
    /// Accepting an unvalidated qualifier makes the domain part user input, so
    /// it carries the same rules the local part does: control characters are
    /// rejected, filter metacharacters are escaped (see
    /// <see cref="SanitizeUsername_OutputCannotAlterFilterStructure"/>).
    /// </summary>
    [Theory]
    [InlineData("jdoe@exa\0mple.com")]
    [InlineData("jdoe@exa\nmple.com")]
    [InlineData("jdoe@exa\tmple.com")]
    public void SanitizeUsername_ControlCharactersInUnvalidatedDomain_Throws(string input)
    {
        Assert.Throws<InvalidCredentialsException>(
            () => LdapPasswordChangeProvider.SanitizeUsername(input));
    }

    /// <summary>
    /// A backslash always separates a qualifier from an account name; it is never
    /// a character within one, because a <c>sAMAccountName</c> cannot contain one.
    ///
    /// <para>This is the visible edge of accepting an unvalidated qualifier: with a
    /// <c>DefaultDomain</c> configured, <c>a\b</c> is rejected because <c>a</c>
    /// contradicts it — but with none configured there is nothing to contradict, and
    /// nothing distinguishes <c>a\b</c> from a genuine <c>EXAMPLE\jdoe</c>, so it is
    /// read the same way and resolves to account <c>b</c>. The account name it
    /// produces still carries the full local-part rules, and a backslash surviving
    /// into that account name is still rejected.</para>
    /// </summary>
    [Theory]
    [InlineData("example.com", @"a\b", null)]           // qualifier contradicts the configured domain
    [InlineData("", @"a\b", "b")]                       // no configured domain: read as DOMAIN\account
    [InlineData("", @"EXAMPLE\jdoe", "jdoe")]           // ... indistinguishable from this
    [InlineData("", @"a\b\c", null)]                    // surviving backslash fails the local-part rules
    [InlineData("", @"EXAMPLE\jd\e", null)]
    public void SanitizeUsername_Backslash_IsAQualifierSeparatorNotAnAccountNameCharacter(
        string defaultDomain, string input, string? expected)
    {
        if (expected is null)
        {
            Assert.Throws<InvalidCredentialsException>(
                () => LdapPasswordChangeProvider.SanitizeUsername(input, defaultDomain));
            return;
        }

        Assert.Equal(expected, LdapPasswordChangeProvider.SanitizeUsername(input, defaultDomain));
    }

    /// <summary>
    /// A username carrying both separators is well-formed in neither syntax.
    /// Splitting it on the backslash would leave two meaningless halves — and
    /// <c>jdoe@exa\mple.com</c> would resolve to an account named
    /// <c>mple.com</c> — so it is rejected outright, in either configuration
    /// state, as it was before qualifiers could be accepted unvalidated.
    /// </summary>
    [Theory]
    [InlineData("", @"jdoe@exa\mple.com")]
    [InlineData("", @"EXAMPLE\jdoe@example.com")]
    [InlineData("example.com", @"jdoe@exa\mple.com")]
    [InlineData("example.com", @"EXAMPLE\jdoe@example.com")]
    public void SanitizeUsername_MixedQualifierSyntax_Throws(string defaultDomain, string input)
    {
        Assert.Throws<InvalidCredentialsException>(
            () => LdapPasswordChangeProvider.SanitizeUsername(input, defaultDomain));
    }

    /// <summary>
    /// Local-part validation is unaffected by which configuration state the
    /// qualifier rules are in: the account name is checked after the qualifier
    /// is resolved, in every row of the matrix.
    /// </summary>
    [Theory]
    [InlineData("", "jd*e@example.com")]
    [InlineData("", "EXAMPLE\\jd,e")]
    [InlineData("", "@example.com")]
    [InlineData("example.com", "jd*e@example.com")]
    [InlineData("example.com", "EXAMPLE\\jd,e")]
    [InlineData("example.com", "@example.com")]
    public void SanitizeUsername_LocalPartValidation_AppliesInEveryQualifierState(
        string defaultDomain, string input)
    {
        Assert.Throws<InvalidCredentialsException>(
            () => LdapPasswordChangeProvider.SanitizeUsername(input, defaultDomain));
    }

    // A backslash is not in this list: it is the DOMAIN\account separator, so it is
    // consumed during qualifier parsing and never reaches the local-part rules —
    // which is exactly why those rules reject one if it survives to the account name
    // (see SanitizeUsername_Backslash_IsAQualifierSeparatorNotAnAccountNameCharacter).
    [Theory]
    [InlineData("jd*e")]
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
    // A qualifier is accepted unvalidated when no DefaultDomain is configured, so
    // it reaches the filter as user input and must be escaped like the local part.
    [InlineData("jdoe@example.com")]
    [InlineData("jdoe@*")]
    [InlineData("jdoe@x)(objectClass=*")]
    [InlineData("jdoe@x\\y")]
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
