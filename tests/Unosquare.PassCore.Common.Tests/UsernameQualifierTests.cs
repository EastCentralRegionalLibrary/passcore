using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Xunit;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// The provider-agnostic qualifier parsing/validation/canonicalization shared by
/// the AD and LDAP providers. Exercised directly here so both providers'
/// behavior for a qualified username rests on one tested implementation rather
/// than on each provider's own copy.
/// </summary>
public class UsernameQualifierTests
{
    private const string RejectionMessage = "rejected";

    [Fact]
    public void BareName_WithConfiguredDomain_IsQualifiedWithIt()
    {
        var result = UsernameQualifier.Resolve("jdoe", "corp.local", RejectionMessage);

        Assert.Equal("jdoe", result.LocalPart);
        Assert.Equal("corp.local", result.DomainPart);
    }

    [Fact]
    public void MatchingUpnSuffix_IsCanonicalizedToTheConfiguredDomain()
    {
        var result = UsernameQualifier.Resolve("jdoe@corp.local", "corp.local", RejectionMessage);

        Assert.Equal("jdoe", result.LocalPart);
        Assert.Equal("corp.local", result.DomainPart);
    }

    [Fact]
    public void MatchingNetBiosPrefix_IsCanonicalizedToTheConfiguredDomain()
    {
        // "corp" is the NetBIOS prefix of "corp.local" (everything before the
        // first '.').
        var result = UsernameQualifier.Resolve("CORP\\jdoe", "corp.local", RejectionMessage);

        Assert.Equal("jdoe", result.LocalPart);
        Assert.Equal("corp.local", result.DomainPart);
    }

    [Fact]
    public void MismatchedQualifier_IsRejected()
    {
        var ex = Assert.Throws<InvalidCredentialsException>(
            () => UsernameQualifier.Resolve("jdoe@other.com", "corp.local", RejectionMessage));

        Assert.Equal(RejectionMessage, ex.Message);
    }

    [Fact]
    public void MismatchedNetBiosQualifier_IsRejected()
    {
        Assert.Throws<InvalidCredentialsException>(
            () => UsernameQualifier.Resolve("OTHERDOMAIN\\jdoe", "corp.local", RejectionMessage));
    }

    [Fact]
    public void BothSeparators_AreRejected()
    {
        var ex = Assert.Throws<InvalidCredentialsException>(
            () => UsernameQualifier.Resolve("CORP\\jdoe@corp.local", "corp.local", RejectionMessage));

        Assert.Equal(RejectionMessage, ex.Message);
    }

    [Fact]
    public void ControlCharactersInTheQualifier_AreRejected()
    {
        Assert.Throws<InvalidCredentialsException>(
            () => UsernameQualifier.Resolve("jdoe@corp.local\0", "corp.local", RejectionMessage));
    }

    [Fact]
    public void UnconfiguredDefaultDomain_KeepsAUpnSuffix()
    {
        var result = UsernameQualifier.Resolve("jdoe@other.com", defaultDomain: null, RejectionMessage);

        Assert.Equal("jdoe", result.LocalPart);
        Assert.Equal("other.com", result.DomainPart);
    }

    [Fact]
    public void UnconfiguredDefaultDomain_DropsANetBiosQualifier()
    {
        var result = UsernameQualifier.Resolve("OTHERDOMAIN\\jdoe", defaultDomain: null, RejectionMessage);

        Assert.Equal("jdoe", result.LocalPart);
        Assert.Null(result.DomainPart);
    }

    // --- FIX 1: a whitespace-only DefaultDomain must behave as unconfigured,
    // never as a literal domain to match against. A stray " " in configuration
    // (nothing trims or validates DefaultDomain before it reaches here) must
    // not lock out every user.

    [Fact]
    public void WhitespaceOnlyDefaultDomain_BehavesAsUnconfigured_KeepsAUpnSuffix()
    {
        var result = UsernameQualifier.Resolve("jdoe@corp.local", defaultDomain: "   ", RejectionMessage);

        Assert.Equal("jdoe", result.LocalPart);
        Assert.Equal("corp.local", result.DomainPart);
    }

    [Fact]
    public void WhitespaceOnlyDefaultDomain_BehavesAsUnconfigured_QualifiesNothing()
    {
        var result = UsernameQualifier.Resolve("jdoe", defaultDomain: "   ", RejectionMessage);

        Assert.Equal("jdoe", result.LocalPart);
        Assert.Null(result.DomainPart);
    }

    [Fact]
    public void WhitespaceOnlyDefaultDomain_BehavesAsUnconfigured_DropsANetBiosQualifier()
    {
        var result = UsernameQualifier.Resolve("OTHERDOMAIN\\jdoe", defaultDomain: "   ", RejectionMessage);

        Assert.Equal("jdoe", result.LocalPart);
        Assert.Null(result.DomainPart);
    }

    [Fact]
    public void EmptyDefaultDomain_IsDistinctFromNull_AndAlsoBehavesAsUnconfigured()
    {
        // The shipped configuration's value (appsettings.json ships
        // DefaultDomain: "") -- exercised separately from null so a future
        // change to the null-handling branch cannot silently stop covering it.
        var result = UsernameQualifier.Resolve("jdoe@corp.local", defaultDomain: "", RejectionMessage);

        Assert.Equal("jdoe", result.LocalPart);
        Assert.Equal("corp.local", result.DomainPart);
    }

    // --- FIX 2: the AD change is wider than "append the domain": it now
    // parses and rewrites DOMAIN\user, which the old AD code had no concept
    // of at all (it only ever appended). Pinned here because both providers'
    // agreement on this rewrite depends on it.

    [Fact]
    public void NetBiosQualifier_WithConfiguredDomain_IsRewrittenToTheUpnForm()
    {
        // CORP\jdoe + DefaultDomain corp.local -> jdoe@corp.local (was
        // CORP\jdoe@corp.local under the old AD append-only code).
        var result = UsernameQualifier.Resolve("CORP\\jdoe", defaultDomain: "corp.local", RejectionMessage);

        Assert.Equal("jdoe", result.LocalPart);
        Assert.Equal("corp.local", result.DomainPart);
    }

    [Fact]
    public void MatchingNetBiosQualifier_WithNoConfiguredDomain_IsDropped()
    {
        // CORP\jdoe + no DefaultDomain -> jdoe (was CORP\jdoe under the old AD
        // append-only code).
        var result = UsernameQualifier.Resolve("CORP\\jdoe", defaultDomain: null, RejectionMessage);

        Assert.Equal("jdoe", result.LocalPart);
        Assert.Null(result.DomainPart);
    }

    [Fact]
    public void UnrelatedNetBiosQualifier_WithNoConfiguredDomain_IsDropped()
    {
        // OTHER\jdoe + no DefaultDomain -> jdoe (was OTHER\jdoe under the old
        // AD append-only code).
        var result = UsernameQualifier.Resolve("OTHER\\jdoe", defaultDomain: null, RejectionMessage);

        Assert.Equal("jdoe", result.LocalPart);
        Assert.Null(result.DomainPart);
    }

    // --- FIX 3: Resolve validates only the qualifier. The local part is left
    // entirely to the caller (LDAP validates it itself; the AD provider now
    // adds its own narrower control-character check). This is a positive
    // pin, not a negative one, because it is the boundary a future refactor
    // is most likely to "helpfully" close.

    [Fact]
    public void LocalPartIsNotValidated_ACommaInItIsReturnedRatherThanRejected()
    {
        var result = UsernameQualifier.Resolve("jdoe,ou=people@corp.local", "corp.local", RejectionMessage);

        Assert.Equal("jdoe,ou=people", result.LocalPart);
        Assert.Equal("corp.local", result.DomainPart);
    }

    [Fact]
    public void EmptyLocalPart_IsReturnedRatherThanRejected()
    {
        // "@corp.local" -- an empty local part. UsernameQualifier does not
        // reject this: the LDAP provider's own local-part checks (empty
        // check, control chars, InvalidAccountNameCharsRegex) are what catch
        // it there, and the AD provider's UPN path relies on FindByIdentity
        // finding no match for an empty account name (UserNotFound), not on
        // this helper.
        var result = UsernameQualifier.Resolve("@corp.local", "corp.local", RejectionMessage);

        Assert.Equal(string.Empty, result.LocalPart);
        Assert.Equal("corp.local", result.DomainPart);
    }
}
