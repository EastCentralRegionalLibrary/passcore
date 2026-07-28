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
