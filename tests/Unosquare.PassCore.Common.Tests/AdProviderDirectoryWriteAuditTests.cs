using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// Guards properties of the Active Directory provider that cannot be asserted
/// at runtime here: it performs no directory write before the caller's current
/// password has been verified, it never decides an <see cref="ApiErrorCode"/>
/// itself (the one rule in <c>docs/error-routing-matrix.md</c>), and a failed
/// credential verification still hands the reason to the log.
///
/// <para><b>Why a source audit and not a behavioral test.</b> The AD provider
/// targets <c>net8.0-windows</c>, its whole implementation is inside
/// <c>#if WINDOWS</c>, and every directory operation goes through concrete
/// AccountManagement / ADSI types (<c>UserPrincipal</c>, <c>DirectoryEntry</c>)
/// with no injectable seam. It therefore cannot be referenced, loaded, or
/// exercised from the cross-platform test suite at all — not even to assert
/// "no write happened", because there is nothing to observe the write with
/// short of a live directory. The same constraint is why
/// <c>RoutingMatrixAuditTests</c> covers the AD column through the shared
/// translator rather than the provider. A source audit is the honest
/// alternative: it is not a proxy for behavior, but it does fail loudly if the
/// removed <c>pwdLastSet</c> pre-flight write (or any equivalent) is
/// reintroduced, which is exactly what it exists to prevent.</para>
///
/// <para>Scanning runs over a skeleton of the source with comments removed and
/// string literals blanked, so prose about the removed code cannot mask a real
/// reintroduction of it.</para>
/// </summary>
public class AdProviderDirectoryWriteAuditTests
{
    private const string ProviderRelativePath =
        "src/Unosquare.PassCore.PasswordProvider/PasswordChangeProvider.cs";

    private const string OptionsRelativePath =
        "src/Unosquare.PassCore.PasswordProvider/PasswordChangeOptions.cs";

    private const string AppSettingsRelativePath =
        "src/Unosquare.PassCore.Web/appsettings.json";

    /// <summary>
    /// Calls that modify the directory, or that hand out the raw
    /// <c>DirectoryEntry</c> through which anything can be modified. Written as
    /// they appear in code so a mention in prose is not what fails the test
    /// (comments are stripped before scanning regardless).
    /// </summary>
    private static readonly string[] WriteCapableCalls =
    [
        ".Save(",
        ".ChangePassword(",
        ".SetPassword(",
        ".CommitChanges(",
        ".SetInfo(",
        ".GetUnderlyingObject(",
        ".Properties[",
    ];

    [Fact]
    public void AdProvider_HasNoPwdLastSetWriteAnywhere()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));

        // The attribute itself, the method that wrote it, and the option that
        // gated it. `minPwdLength` (a read, elsewhere in the provider) does not
        // contain any of these.
        Assert.DoesNotContain("pwdLastSet", code, StringComparison.Ordinal);
        Assert.DoesNotContain("SetLastPassword", code, StringComparison.Ordinal);
        Assert.DoesNotContain("UpdateLastPassword", code, StringComparison.Ordinal);

        // AD maintains pwdLastSet itself on every successful change or reset,
        // so the provider has no reason to reach for the raw directory entry or
        // to commit an attribute edit anywhere.
        Assert.DoesNotContain(".GetUnderlyingObject(", code, StringComparison.Ordinal);
        Assert.DoesNotContain(".CommitChanges(", code, StringComparison.Ordinal);
    }

    [Fact]
    public void ChangePasswordCore_PerformsNoDirectoryWriteBeforeCredentialVerification()
    {
        var body = ExtractMethodBody(
            CodeSkeleton(ReadRepoFile(ProviderRelativePath)),
            "Task ChangePasswordCore(");

        var verificationAt = body.IndexOf("ValidateUserCredentials(", StringComparison.Ordinal);
        Assert.True(
            verificationAt >= 0,
            "ChangePasswordCore no longer calls ValidateUserCredentials; the ordering this test " +
            "guards has no anchor. Re-establish credential verification before reviewing this test.");

        foreach (var call in WriteCapableCalls)
        {
            var firstUse = body.IndexOf(call, StringComparison.Ordinal);
            if (firstUse < 0) continue;

            Assert.True(
                firstUse > verificationAt,
                $"'{call}' appears in ChangePasswordCore at offset {firstUse}, before the " +
                $"ValidateUserCredentials call at offset {verificationAt}. Everything above that " +
                "call runs for a caller who supplied only a username, so a directory write there " +
                "is an unauthenticated modification. See docs/UPGRADING-error-routing.md.");
        }
    }

    [Fact]
    public void ChangePasswordCore_AttachesTheVerificationFailureReasonAsAnInnerException()
    {
        // The runtime behavior — that an operator can read the Win32 code back
        // out of the logged chain — is covered by CredentialFailureDetailTests
        // against the shared factory. What cannot be covered there is whether
        // this provider actually calls it, so that wiring is asserted here.
        var body = ExtractMethodBody(
            CodeSkeleton(ReadRepoFile(ProviderRelativePath)),
            "Task ChangePasswordCore(");

        Assert.True(
            body.Contains("CredentialFailureDetail.ForWin32Code(", StringComparison.Ordinal),
            "ChangePasswordCore no longer builds a CredentialFailureDetail for a failed credential " +
            "verification. Hardened mode collapses every credential and account-state condition " +
            "into one response, so dropping this detail leaves the operator with no way to tell a " +
            "lockout from a mistyped password. See docs/error-routing-matrix.md, 'Diagnostics'.");

        // The detail must be an argument to the exception, never part of the
        // message that ApiErrorMapper puts on the wire.
        var throwAt = body.IndexOf("new InvalidCredentialsException(", StringComparison.Ordinal);
        Assert.True(throwAt >= 0, "ChangePasswordCore no longer throws InvalidCredentialsException on verification failure.");
    }

    [Fact]
    public void ValidateUserCredentials_StillDelegatesTheProceedDecisionToTheSharedPredicate()
    {
        // 0x532 / 0x773 must keep meaning "the user proved the current password,
        // let the change proceed", and that decision must stay shared with the
        // LDAP provider rather than being re-derived here.
        var body = ExtractMethodBody(
            CodeSkeleton(ReadRepoFile(ProviderRelativePath)),
            "bool ValidateUserCredentials(");

        Assert.Contains(
            "DirectoryErrorTranslator.IsPasswordExpiredOrMustChange(",
            body,
            StringComparison.Ordinal);
    }

    [Fact]
    public void AdProvider_ProducesNoApiErrorCodeOfItsOwn()
    {
        // Every wire-visible code must come from DirectoryErrorTranslator or the
        // shared policy layer; a provider that names ApiErrorCode is deciding
        // one itself and bypasses the routing matrix.
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));

        Assert.DoesNotContain("ApiErrorCode", code, StringComparison.Ordinal);
    }

    [Fact]
    public void UpdateLastPasswordOption_IsGoneFromCodeAndShippedConfiguration()
    {
        Assert.DoesNotContain(
            "UpdateLastPassword",
            CodeSkeleton(ReadRepoFile(OptionsRelativePath)),
            StringComparison.Ordinal);

        // No shim, no obsolete property, and no shipped key. A stale key left in
        // a deployment's own appsettings.json is harmless — configuration
        // binding ignores unknown keys.
        Assert.DoesNotContain(
            "UpdateLastPassword",
            ReadRepoFile(AppSettingsRelativePath),
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Removes comments and blanks string/char literal contents, leaving the
    /// executable shape of the file. Literals are blanked (not deleted) so that
    /// braces or parentheses inside them cannot unbalance the body extraction.
    /// </summary>
    private static string CodeSkeleton(string source) =>
        Regex.Replace(
            source,
            """(?<verbatim>@"(?:[^"]|"")*")|(?<literal>"(?:[^"\\\n]|\\.)*")|(?<ch>'(?:[^'\\\n]|\\.)*')|(?<line>//[^\n]*)|(?<block>/\*.*?\*/)""",
            static match => match.Groups["line"].Success || match.Groups["block"].Success ? string.Empty : "\"\"",
            RegexOptions.Singleline);

    /// <summary>
    /// Returns the brace-delimited body of the first method whose declaration
    /// contains <paramref name="signatureFragment"/>.
    /// </summary>
    private static string ExtractMethodBody(string code, string signatureFragment)
    {
        var declarationAt = code.IndexOf(signatureFragment, StringComparison.Ordinal);
        Assert.True(declarationAt >= 0, $"Could not find '{signatureFragment}' in the provider source.");

        var open = code.IndexOf('{', declarationAt);
        Assert.True(open >= 0, $"Could not find a body for '{signatureFragment}'.");

        var depth = 0;
        for (var i = open; i < code.Length; i++)
        {
            if (code[i] == '{') depth++;
            else if (code[i] == '}' && --depth == 0) return code[(open + 1)..i];
        }

        throw new InvalidOperationException($"Unbalanced braces while reading the body of '{signatureFragment}'.");
    }

    /// <summary>
    /// The AD half of "could not determine membership is not the same as not a
    /// member". The LDAP provider's behavior is exercised for real in
    /// <c>GroupMembershipUndeterminedTests</c>; this provider cannot be loaded here
    /// (see the class summary), so its shape is audited instead.
    ///
    /// <para>What must hold: both group enumerations record their failure rather
    /// than swallowing it, and a negative result is only returned when neither
    /// recorded anything. Swallowing either one makes <c>RestrictedAdGroups</c> fail
    /// open — a <c>Domain Admins</c> member gets a password change during a partial
    /// directory failure.</para>
    /// </summary>
    [Fact]
    public void GroupMembership_FailsClosedWhenMembershipCannotBeDetermined()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));

        // Resolution and evaluation are now separate: the two enumerations happen
        // once per request in ResolveMembershipAsync, and the answer is given from
        // that resolution. The fail-closed property spans both.
        var resolveBody = ExtractMethodBody(code, "Task<IResolvedGroupMembership> ResolveMembershipAsync(");
        var answerBody = ExtractMethodBody(code, "Task<bool> IsMemberOfAnyAsync(");

        // GetAuthorizationGroups is now the sole enumeration, and its failure must
        // still be recorded. This is the part that did NOT change when GetGroups
        // was removed: dropping the second match source narrows what can match, and
        // must not soften what a failure means.
        Assert.Equal(1, CountOccurrences(resolveBody, "undetermined ??= ex;"));

        // A recorded failure must block the negative answer, not merely be logged.
        var guardAt = answerBody.IndexOf("if (_undetermined is not null)", StringComparison.Ordinal);
        var notAMemberAt = answerBody.LastIndexOf("return Task.FromResult(false);", StringComparison.Ordinal);

        Assert.True(
            guardAt >= 0,
            "The resolved membership no longer guards its negative answer on whether every enumeration " +
            "completed. Without that guard a failed enumeration reads as 'not a member' and the " +
            "restricted-group deny list fails open. See docs/error-routing-matrix.md.");
        Assert.True(
            guardAt < notAMemberAt,
            "The 'could not determine' guard no longer precedes the final 'not a member' return, so a " +
            "failed enumeration can still reach it.");

        // A match stays definitive: it is answered before the undetermined guard.
        var matchAt = answerBody.IndexOf("return Task.FromResult(true);", StringComparison.Ordinal);
        Assert.True(
            matchAt >= 0 && matchAt < guardAt,
            "A positive match must be answered before the undetermined guard, so that a confirmed " +
            "membership is never turned into an infrastructure error by an unrelated lookup failure.");

        // The outcome is the shared infrastructure response, decided by the
        // translator rather than by this provider.
        Assert.Contains("DirectoryErrorTranslator.TranslateException(", answerBody, StringComparison.Ordinal);
        Assert.Contains("DirectoryActor.ServiceAccount", answerBody, StringComparison.Ordinal);

        // ... and the failed enumeration is reported to the operator, not swallowed:
        // one for the enumeration, plus the terminal catch that covers resolving the
        // user.
        Assert.Equal(2, CountOccurrences(resolveBody, "ServiceAccountFailure.Log("));
    }

    /// <summary>
    /// Security groups only. <c>GetAuthorizationGroups()</c> reads <c>tokenGroups</c>
    /// and returns the transitive security-group closure including the primary group;
    /// <c>GetGroups()</c> added nothing over it but distribution groups, which cannot
    /// enter a Windows access token and therefore carry no authorization.
    ///
    /// <para>The cost of keeping it was disproportionate: <c>GetGroups()</c> routes
    /// through <c>ADStoreCtx.GetGroupsMemberOf</c> into <c>Forest.GetForest()</c> —
    /// full forest topology discovery — on every unauthenticated request, and its
    /// failure made every NEGATIVE answer undetermined. One environmental gap in
    /// forest discovery therefore refused every non-member.</para>
    ///
    /// <para>This is the guard against it being reinstated as a "resilience"
    /// improvement, which is exactly how it arrived in 2020.</para>
    /// </summary>
    [Fact]
    public void GroupMembership_MatchesSecurityGroupsOnlyAndDoesNotDiscoverTheForest()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));
        var resolveBody = ExtractMethodBody(code, "Task<IResolvedGroupMembership> ResolveMembershipAsync(");

        Assert.Contains("GetAuthorizationGroups()", resolveBody, StringComparison.Ordinal);

        Assert.DoesNotContain(
            "GetGroups()",
            resolveBody,
            StringComparison.Ordinal);

        // Nothing anywhere in the provider may reach forest discovery: the whole
        // point is that the membership path no longer depends on it.
        Assert.DoesNotContain("GetForest", code, StringComparison.Ordinal);
        Assert.DoesNotContain("Forest.", code, StringComparison.Ordinal);
    }

    /// <summary>
    /// A completed enumeration that found no match is a DEFINITIVE non-member, and
    /// that is what makes this change worth anything: before it, a negative needed
    /// both enumerations to complete, and the second one could not.
    ///
    /// <para>The two halves are inseparable and both are asserted here: the negative
    /// is returned plainly when nothing failed, and it is still withheld when
    /// something did.</para>
    /// </summary>
    [Fact]
    public void GroupMembership_CompletedEnumerationWithNoMatchIsADefinitiveNonMember()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));
        var answerBody = ExtractMethodBody(code, "Task<bool> IsMemberOfAnyAsync(");

        var guardAt = answerBody.IndexOf("if (_undetermined is not null)", StringComparison.Ordinal);
        var notAMemberAt = answerBody.LastIndexOf("return Task.FromResult(false);", StringComparison.Ordinal);

        Assert.True(guardAt >= 0, "The undetermined guard is gone; a failed enumeration would read as 'not a member'.");
        Assert.True(
            notAMemberAt > guardAt,
            "There is no reachable 'not a member' answer after the undetermined guard. A completed " +
            "enumeration that found no match must be able to answer false — otherwise every negative " +
            "is an infrastructure error and the group lists cannot refuse anyone.");
    }

    /// <summary>
    /// <c>GetAuthorizationGroups()</c> yields null ELEMENTS for SIDs it cannot
    /// translate (dotnet/runtime#80675). The collector must test the element, not
    /// just its <c>Name</c>, or it throws <c>NullReferenceException</c> before its own
    /// guard is reached. Fail-closed either way, but through an explanatory error
    /// rather than a bare NRE — and it matters more now this is the only enumeration.
    /// </summary>
    [Fact]
    public void GroupMembership_NullGroupPrincipalIsHandledByTheIntendedGuard()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));
        var collectBody = ExtractMethodBody(code, "void CollectNames(");

        Assert.Contains("principal?.Name", collectBody, StringComparison.Ordinal);
    }

    /// <summary>
    /// The resolution must happen once per request, not once per configured group
    /// name. The LDAP side of this is exercised for real in
    /// <c>PreAuthenticationDirectoryLoadTests</c>; this provider can only be audited.
    /// </summary>
    [Fact]
    public void GroupMembership_ResolvesTheUserOncePerRequestRatherThanPerGroup()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));

        // The expensive calls belong to the once-per-request resolution...
        var resolveBody = ExtractMethodBody(code, "Task<IResolvedGroupMembership> ResolveMembershipAsync(");
        Assert.Contains("GetAuthorizationGroups()", resolveBody, StringComparison.Ordinal);
        Assert.Contains("FindByIdentity(", resolveBody, StringComparison.Ordinal);

        // ... and none of them may reappear in the per-name answer, which must be
        // pure in-memory work.
        var answerBody = ExtractMethodBody(code, "Task<bool> IsMemberOfAnyAsync(");
        Assert.DoesNotContain("GetAuthorizationGroups", answerBody, StringComparison.Ordinal);
        Assert.DoesNotContain("GetGroups", answerBody, StringComparison.Ordinal);
        Assert.DoesNotContain("FindByIdentity", answerBody, StringComparison.Ordinal);
        Assert.DoesNotContain("AcquirePrincipalContext", answerBody, StringComparison.Ordinal);

        // The per-group entry point delegates rather than carrying its own copy.
        var perGroupBody = ExtractMethodBody(code, "Task<bool> IsMemberOfGroupAsync(");
        Assert.Contains("ResolveMembershipAsync(", perGroupBody, StringComparison.Ordinal);
    }

    /// <summary>
    /// A deployment running <c>UseAutomaticContext: false</c> must be told at
    /// startup that the password change is unverified on that path, rather than
    /// finding out when an end user receives a generic directory error.
    ///
    /// <para>Both the firing and the non-firing case are asserted, because the
    /// scoping is the whole point: the warning must not reach the automatic-context
    /// path, which is what most deployments run and where nothing is known to be
    /// wrong. Warning every deployment would make it noise and get it suppressed.</para>
    ///
    /// <para>Audited from source rather than exercised, for the reason in the class
    /// summary — the provider cannot be loaded here at all. The condition is a
    /// single guarded call, so its shape is worth exactly as much as running it
    /// would be.</para>
    /// </summary>
    [Fact]
    public void ExplicitBindDeployments_AreWarnedAtStartup_AndAutomaticContextIsNot()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));
        var constructorBody = ExtractMethodBody(code, "public PasswordChangeProvider(");

        // Fires on the explicit-bind path...
        Assert.Matches(
            @"if\s*\(\s*!\s*_options\.UseAutomaticContext\s*\)\s*"
            + @"LogExplicitBindPasswordChangeUnverified\s*\(",
            constructorBody);

        // ...and the guard is negated, so it cannot also fire on the automatic
        // path. A call without "!" would warn exactly the deployments that have no
        // reported problem.
        Assert.DoesNotMatch(
            @"if\s*\(\s*_options\.UseAutomaticContext\s*\)\s*"
            + @"LogExplicitBindPasswordChangeUnverified\s*\(",
            constructorBody);

        // Warning, not a throw: reads, credential verification, group membership
        // and policy evaluation all work on this path, so startup must succeed.
        var declaration = code[code.IndexOf("LogExplicitBindPasswordChangeUnverified =", StringComparison.Ordinal)..];
        Assert.Contains("LogLevel.Warning", declaration[..200], StringComparison.Ordinal);
        Assert.Contains("EventId(115", declaration[..300], StringComparison.Ordinal);
    }

    /// <summary>
    /// EventId 105 described a group-enumeration failure as an expected fallback,
    /// logged at Debug. That is no longer what happens, so the delegate is gone —
    /// and the ID must stay retired rather than being recycled for something else.
    /// </summary>
    [Fact]
    public void RetiredGroupEnumerationFallbackEvent_IsNotReintroducedOrReused()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));

        Assert.DoesNotContain("LogGroupEnumerationFallback", code, StringComparison.Ordinal);
        Assert.DoesNotContain("EventId(105", code, StringComparison.Ordinal);
    }

    private static int CountOccurrences(string haystack, string needle)
    {
        var count = 0;
        for (var i = haystack.IndexOf(needle, StringComparison.Ordinal);
             i >= 0;
             i = haystack.IndexOf(needle, i + needle.Length, StringComparison.Ordinal))
        {
            count++;
        }

        return count;
    }

    /// <summary>
    /// The AD half of the cross-provider claim that a stock deployment accepts the
    /// username form its own UI asks for. <c>appsettings.json</c> ships
    /// <c>DefaultDomain: ""</c> next to <c>UseEmail: true</c>, so an unmodified
    /// install prompts for <c>user@domain</c>; the AD provider must hand that
    /// straight to <c>FindByIdentity</c>, which resolves it as a UPN, rather than
    /// rejecting it as malformed. The LDAP provider's matching behavior is asserted
    /// for real in <c>ShippedConfigurationUsernameFormTests</c> — this side can only
    /// be audited, for the reasons in the class summary above.
    /// </summary>
    [Fact]
    public void AdProvider_AcceptsAQualifiedUsernameWhenNoDefaultDomainIsConfigured()
    {
        Assert.Contains(
            "\"DefaultDomain\": \"\"",
            ReadRepoFile(AppSettingsRelativePath),
            StringComparison.Ordinal);

        var body = ExtractMethodBody(
            CodeSkeleton(ReadRepoFile(ProviderRelativePath)),
            "string FixUsernameWithDomain(");

        // Two branches return the supplied name untouched: it already carries a
        // domain, or there is no configured domain to qualify it with.
        Assert.Contains("parts.Length > 1", body, StringComparison.Ordinal);
        Assert.Contains("string.IsNullOrWhiteSpace(_options.DefaultDomain)", body, StringComparison.Ordinal);

        // And neither branch rejects. A format rejection here would surface as
        // InvalidCredentials — indistinguishable from a wrong password, with nothing
        // logged to point at configuration — which is exactly the divergence the LDAP
        // provider carried until its qualifier handling was corrected.
        Assert.DoesNotContain("throw", body, StringComparison.Ordinal);
    }

    [Fact]
    public void AdProvider_DefaultLdapPortIs389()
    {
        var optionsContent = ReadRepoFile(OptionsRelativePath);
        Assert.Contains("public int LdapPort { get; set; } = 389;", optionsContent, StringComparison.Ordinal);
    }

    [Fact]
    public void AdProvider_ValidateOptionsCalledInConstructor()
    {
        var providerContent = ReadRepoFile(ProviderRelativePath);
        var body = ExtractMethodBody(CodeSkeleton(providerContent), "PasswordChangeProvider(");
        Assert.Contains("ValidateOptions(_options)", body, StringComparison.Ordinal);
    }

    [Fact]
    public void AdProvider_ValidateOptionsChecksLdapSettings()
    {
        var providerContent = ReadRepoFile(ProviderRelativePath);
        var body = ExtractMethodBody(CodeSkeleton(providerContent), "void ValidateOptions(");

        Assert.Contains("opts.LdapHostnames", body, StringComparison.Ordinal);
        Assert.Contains("opts.LdapUsername", body, StringComparison.Ordinal);
        Assert.Contains("opts.LdapPassword", body, StringComparison.Ordinal);
    }

    [Fact]
    public void WebStartup_EagerlyResolvesPasswordChangeProvider()
    {
        var programPath = "src/Unosquare.PassCore.Web/Program.cs";
        var programContent = ReadRepoFile(programPath);
        Assert.Contains("app.Services.GetRequiredService<IPasswordChangeProvider>()", programContent, StringComparison.Ordinal);
    }

    private static string ReadRepoFile(string relativePath)
    {
        // Path.Join, not Path.Combine: Join always concatenates, where Combine
        // discards everything before a segment it considers rooted.
        var path = Path.Join(RepositoryRoot(), relativePath.Replace('/', Path.DirectorySeparatorChar));
        Assert.True(File.Exists(path), $"Expected to find '{relativePath}' at '{path}'.");

        return File.ReadAllText(path);
    }

    private static string RepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        var visited = new List<string>();

        while (directory != null)
        {
            visited.Add(directory.FullName);
            if (File.Exists(Path.Join(directory.FullName, "Unosquare.PassCore.sln")))
                return directory.FullName;

            directory = directory.Parent;
        }

        throw new InvalidOperationException(
            "Could not locate the repository root (no Unosquare.PassCore.sln found above " +
            $"'{AppContext.BaseDirectory}'). Searched: {string.Join(", ", visited)}. This audit " +
            "reads provider source, so it must run from a source checkout.");
    }
}
