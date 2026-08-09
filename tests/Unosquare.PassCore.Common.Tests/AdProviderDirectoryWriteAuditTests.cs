using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using static Unosquare.PassCore.Testing.RepositorySource;

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

    private const string BaseRelativePath =
        "src/Unosquare.PassCore.Common/DirectoryPasswordChangeProviderBase.cs";

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

        // Both actual password writes go through the bound entry's
        // reflection-style Invoke("ChangePassword", ...) /
        // Invoke("SetPassword", ...), not through .ChangePassword(/.SetPassword(
        // above — those match the AccountManagement principal API, not the
        // ADSI DirectoryEntry calls this provider actually uses for the write.
        // Without this entry, a write moved before credential verification via
        // Invoke would go undetected by this audit.
        ".Invoke(",
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
    public void ChangeDirectoryPasswordCore_PerformsNoDirectoryWriteBeforeCredentialVerification()
    {
        var body = ExtractMethodBody(
            CodeSkeleton(ReadRepoFile(ProviderRelativePath)),
            "Task ChangeDirectoryPasswordCore(");

        var verificationAt = body.IndexOf("ValidateUserCredentials(", StringComparison.Ordinal);
        Assert.True(
            verificationAt >= 0,
            "ChangeDirectoryPasswordCore no longer calls ValidateUserCredentials; the ordering this test " +
            "guards has no anchor. Re-establish credential verification before reviewing this test.");

        var foundAny = false;
        foreach (var call in WriteCapableCalls)
        {
            var firstUse = body.IndexOf(call, StringComparison.Ordinal);
            if (firstUse < 0) continue;

            foundAny = true;
            Assert.True(
                firstUse > verificationAt,
                $"'{call}' appears in ChangeDirectoryPasswordCore at offset {firstUse}, before the " +
                $"ValidateUserCredentials call at offset {verificationAt}. Everything above that " +
                "call runs for a caller who supplied only a username, so a directory write there " +
                "is an unauthenticated modification. See docs/UPGRADING-error-routing.md.");
        }

        Assert.True(
            foundAny,
            "No write-capable tokens were found in ChangeDirectoryPasswordCore's body. The audit " +
            "is vacuous and offers no protection against unauthorized modifications.");
    }

    [Fact]
    public void ChangeDirectoryPasswordCore_AttachesTheVerificationFailureReasonAsAnInnerException()
    {
        // The runtime behavior — that an operator can read the Win32 code back
        // out of the logged chain — is covered by CredentialFailureDetailTests
        // against the shared factory. What cannot be covered there is whether
        // this provider actually calls it, so that wiring is asserted here.
        var body = ExtractMethodBody(
            CodeSkeleton(ReadRepoFile(ProviderRelativePath)),
            "Task ChangeDirectoryPasswordCore(");

        Assert.True(
            body.Contains("CredentialFailureDetail.ForWin32Code(", StringComparison.Ordinal),
            "ChangeDirectoryPasswordCore no longer builds a CredentialFailureDetail for a failed credential " +
            "verification. Hardened mode collapses every credential and account-state condition " +
            "into one response, so dropping this detail leaves the operator with no way to tell a " +
            "lockout from a mistyped password. See docs/error-routing-matrix.md, 'Diagnostics'.");

        // The detail must be an argument to the exception, never part of the
        // message that ApiErrorMapper puts on the wire.
        var throwAt = body.IndexOf("new InvalidCredentialsException(", StringComparison.Ordinal);
        Assert.True(throwAt >= 0, "ChangeDirectoryPasswordCore no longer throws InvalidCredentialsException on verification failure.");
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
    /// A deployment running <c>UseAutomaticContext: false</c> must be told at
    /// startup that its password writes depend on LDAPS and therefore on
    /// certificate trust, rather than finding out when an end user receives a
    /// generic directory error.
    ///
    /// <para>Nothing else PassCore does exercises that trust — reads, credential
    /// verification and group membership all go over the sign-and-seal context —
    /// so a deployment can be healthy in every observable way and still have no
    /// working write. That is precisely the condition a startup warning is for.</para>
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

        // Fires on the explicit-bind path.
        Assert.Matches(
            @"if\s*\(\s*!\s*_options\.UseAutomaticContext\s*\)[\s\S]{0,400}?"
            + @"LogLdapsWriteRequired\s*\(",
            constructorBody);

        // ...and the guard is negated, so it cannot also fire on the automatic
        // path. A call without "!" would warn exactly the deployments that have no
        // reported problem.
        Assert.DoesNotMatch(
            @"if\s*\(\s*_options\.UseAutomaticContext\s*\)[\s\S]{0,400}?"
            + @"LogLdapsWriteRequired\s*\(",
            constructorBody);

        // Warning, not a throw: everything on this path works, including the
        // write, provided the certificate is trusted — so startup must succeed.
        var declaration = code[code.IndexOf("LogLdapsWriteRequired =", StringComparison.Ordinal)..];
        Assert.Contains("LogLevel.Warning", declaration[..200], StringComparison.Ordinal);
        Assert.Contains("EventId(115", declaration[..300], StringComparison.Ordinal);
        Assert.DoesNotContain("throw new", constructorBody, StringComparison.Ordinal);
    }

    /// <summary>
    /// EventId 117 announced at startup that no password write could succeed with
    /// this provider on an explicit bind from a host that is not domain-joined,
    /// unless a domain controller was reachable over RPC/SMB.
    ///
    /// <para>Both halves are now false. The write binds its own LDAPS entry, which
    /// was measured to succeed in exactly that combination, and RPC was where ADSI
    /// ended up when it was given a 389-bound entry — not something it needed. A
    /// warning that declares a working configuration hopeless, and asks for a
    /// firewall opening nobody needs, is worse than no warning; a DMZ deployment
    /// reading it would conclude PassCore could not serve AD at all.</para>
    ///
    /// <para>The ID stays retired rather than being recycled, so that an aggregated
    /// log containing both old and new events can never show two different claims
    /// under one number.</para>
    /// </summary>
    [Fact]
    public void RetiredNoWorkingWritePathEvent_IsNotReintroducedOrReused()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));

        Assert.DoesNotContain("LogNoWorkingPasswordWritePath", code, StringComparison.Ordinal);
        Assert.DoesNotContain("EventId(117", code, StringComparison.Ordinal);
    }

    /// <summary>
    /// The point of the whole change: a password write is made on a connection this
    /// provider bound over LDAPS, not on whichever connection the
    /// <c>AccountManagement</c> principal happens to be carrying.
    ///
    /// <para>Measured, not assumed. From a host that is not domain-joined, against
    /// the same directory in the same run: on an entry bound sign-and-seal on 389
    /// the change failed <c>0x80070547</c> having never contacted the directory and
    /// the reset fell through to RPC and failed <c>0x800706BA</c>; on an LDAPS-bound
    /// entry both succeeded, and the directory logged them as ordinary LDAP password
    /// modifications attributed to the target user.</para>
    ///
    /// <para>Both writes are covered. Scoping the fix to the reset alone would have
    /// left the ordinary change — the thing PassCore exists to do — still broken on
    /// that path, and the reset is gated on <c>ChangeNotPermitted</c> so it would
    /// never have fired for it anyway.</para>
    /// </summary>
    [Fact]
    public void BothPasswordWrites_GoOverAnLdapsBoundEntry()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));

        foreach (var (method, signature) in new[]
                 {
                     ("the ordinary change", "void UpdatePassword("),
                     ("the administrative reset", "void PerformAdministrativeReset("),
                 })
        {
            var body = ExtractMethodBody(code, signature);

            Assert.True(
                body.Contains("BindForWrite(", StringComparison.Ordinal),
                $"{method} no longer binds its own directory entry for the write. It would then go " +
                "out on whatever connection the principal carries, which is the sign-and-seal " +
                "context — measured to fail on a host that is not domain-joined.");

            Assert.True(
                body.Contains(".Invoke(", StringComparison.Ordinal),
                $"{method} no longer performs the write through the bound entry.");
        }

        // The bind must be LDAPS, and the port must come from the shared
        // substitution rather than being written out here: 389 upgrades in band and
        // is not listening for a TLS ClientHello, so pointing SecureSocketsLayer at
        // the configured port directly fails 0x8007203A on every default deployment.
        var bindBody = ExtractMethodBody(code, "DirectoryEntry? BindForWrite(");

        Assert.Contains("AuthenticationTypes.SecureSocketsLayer", bindBody, StringComparison.Ordinal);
        Assert.Contains("LdapChannelPorts.SslPortFor(_options.LdapPort)", bindBody, StringComparison.Ordinal);

        // Certificate validation is never suppressed to make the bind succeed. A
        // write nobody can authenticate is not a fix.
        Assert.DoesNotContain("ServerBind", code, StringComparison.Ordinal);
        Assert.DoesNotContain("ServerCertificate", code, StringComparison.Ordinal);
        Assert.DoesNotContain("VerifyServerCertificate", code, StringComparison.Ordinal);
    }

    /// <summary>
    /// The LDAPS bind is an improvement, not a new prerequisite: a deployment whose
    /// directory has no usable LDAPS must keep behaving exactly as it did before.
    /// So a bind failure falls back to the principal-based call rather than
    /// surfacing as a failed password change.
    ///
    /// <para>The bind is therefore forced while the entry is being built, not left
    /// to happen lazily inside <c>Invoke</c>. <c>DirectoryEntry</c> connects on
    /// first use, so without that a certificate failure would arrive from the same
    /// call as "the directory rejected this password" — and falling back there would
    /// mean re-attempting a change the directory has already refused, against a
    /// domain that may count it as another failed attempt.</para>
    /// </summary>
    [Fact]
    public void AFailedLdapsBind_FallsBackInsteadOfFailingTheChange()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));
        var bindBody = ExtractMethodBody(code, "DirectoryEntry? BindForWrite(");

        // Forced eagerly, inside the try, so the failure is attributable.
        var refreshAt = bindBody.IndexOf("RefreshCache(", StringComparison.Ordinal);
        var catchAt = bindBody.IndexOf("catch (Exception bindFailure)", StringComparison.Ordinal);

        Assert.True(
            refreshAt >= 0,
            "BindForWrite no longer forces the bind. DirectoryEntry connects lazily, so the bind " +
            "failure would surface from Invoke instead, where it cannot be told apart from the " +
            "directory rejecting the password.");
        Assert.True(refreshAt < catchAt, "The forced bind is no longer inside the guarded region.");

        // The failure returns null — the caller's signal to use the old path — and
        // never propagates as a change failure.
        Assert.Contains("return null;", bindBody[catchAt..], StringComparison.Ordinal);

        // And the callers honour it.
        foreach (var signature in new[] { "void UpdatePassword(", "void PerformAdministrativeReset(" })
        {
            var body = ExtractMethodBody(code, signature);
            Assert.True(
                body.Contains("entry is null", StringComparison.Ordinal),
                $"'{signature}' no longer has a fallback branch for an unbindable entry, so a " +
                "deployment without usable LDAPS would lose a write path it has today.");
        }
    }

    /// <summary>
    /// A failed LDAPS bind is silent to the end user by design — it falls back — so
    /// the log is the only place it can be seen. It has to name the port and carry
    /// the reason, because those are what separate the two very different causes:
    /// an unreachable 636 is a firewall or a directory not offering LDAPS, while a
    /// certificate failure is trust on the machine PassCore runs on.
    /// </summary>
    [Fact]
    public void TheLdapsBindFailure_NamesThePortAndCarriesTheReason()
    {
        var source = ReadRepoFile(ProviderRelativePath);
        var declaration = source[source.IndexOf("LogLdapsWriteBindFailed =", StringComparison.Ordinal)..];
        var message = declaration[..declaration.IndexOf(");", StringComparison.Ordinal)];

        Assert.Contains("LogLevel.Warning", message, StringComparison.Ordinal);
        Assert.Contains("EventId(119", message, StringComparison.Ordinal);
        Assert.Contains("{Port}", message, StringComparison.Ordinal);
        Assert.Contains("{Host}", message, StringComparison.Ordinal);

        // The reason travels as the exception argument, which reaches the log and
        // never the wire. A delegate with no Exception parameter cannot carry it.
        var bindBody = ExtractMethodBody(
            CodeSkeleton(source), "DirectoryEntry? BindForWrite(");

        Assert.Contains(
            "LogLdapsWriteBindFailed(Logger, correlationId, operation, host, port, bindFailure)",
            bindBody,
            StringComparison.Ordinal);

        // ...and the successful path says so too, so "which transport did this
        // write actually use" is answerable from the log either way.
        Assert.Contains(
            "LogPasswordWriteOverLdaps(Logger, correlationId, operation, host, port, null)",
            bindBody,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The service-account context is NOT moved to LDAPS. It leads with
    /// sign-and-seal, which encrypts through the negotiated security package and
    /// needs no certificate trust at all, so every read PassCore makes keeps working
    /// on directories whose certificate this machine cannot validate. Only the write
    /// — the one operation measured to need it — pays that cost.
    /// </summary>
    [Fact]
    public void TheServiceAccountContext_StillLeadsWithSignAndSeal()
    {
        var body = ExtractMethodBody(
            CodeSkeleton(ReadRepoFile(ProviderRelativePath)), "PrincipalContext AcquirePrincipalContext(");

        var sealedAt = body.IndexOf("ContextOptions.Sealing", StringComparison.Ordinal);
        var sslAt = body.IndexOf("ContextOptions.SecureSocketLayer", StringComparison.Ordinal);

        Assert.True(sealedAt >= 0, "The service-account context no longer attempts a signed-and-sealed bind.");
        Assert.True(
            sslAt > sealedAt,
            "SSL is no longer the fallback for the service-account context. Leading with it would " +
            "make certificate trust a prerequisite for every directory read, to fix the write.");
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
    /// <summary>
    /// The load-bearing fact behind the shipped-config claim is not "the body
    /// contains no 'throw'" -- rejection moved INSIDE
    /// <c>UsernameQualifier.Resolve</c>, so that proves nothing about this
    /// method's own name and would still pass if the call were changed to a
    /// hardcoded domain. What actually has to hold is that
    /// <c>FixUsernameWithDomain</c> passes <c>_options.DefaultDomain</c>
    /// unaltered as the domain argument, and references no other domain
    /// source -- so with the shipped <c>DefaultDomain: ""</c>, the behavior
    /// this test title describes is exactly
    /// <c>UsernameQualifierTests.UnconfiguredDefaultDomain_KeepsAUpnSuffix</c>,
    /// which is the behavioral half of this pin.
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

        // Whitespace-normalized so formatting (line breaks, extra spaces
        // around the call) cannot mask a changed argument.
        var normalizedBody = Regex.Replace(body, @"\s+", " ").Trim();

        Assert.Contains(
            "UsernameQualifier.Resolve( username, _options.DefaultDomain,",
            normalizedBody,
            StringComparison.Ordinal);

        // No other domain source feeds the call: a hardcoded string or a
        // different option would still leave "throw" absent from this method
        // and pass a weaker check.
        Assert.DoesNotContain("_options.LdapHostnames", body, StringComparison.Ordinal);
    }

    /// <summary>
    /// Pins the behavior change this batch made: <c>FixUsernameWithDomain</c> keeps
    /// its early return for every identity type except
    /// <c>IdentityType.UserPrincipalName</c> — <c>DistinguishedName</c>, <c>Guid</c>,
    /// <c>Sid</c> and <c>SamAccountName</c> lookups get the supplied username back
    /// completely unchanged, with no validation — and on the
    /// <c>UserPrincipalName</c> path it now routes through the shared
    /// <c>UsernameQualifier</c> rather than the old three-line "append the domain if
    /// there's no '@'" check, so a mismatched domain qualifier or a control
    /// character reaches <c>UsernameQualifier.Resolve</c> (and is rejected there)
    /// instead of being handed straight to <c>FindByIdentity</c>.
    /// </summary>
    [Fact]
    public void AdProvider_FixUsernameWithDomain_EarlyReturnsForNonUpnAndRoutesUpnThroughSharedQualifier()
    {
        var body = ExtractMethodBody(
            CodeSkeleton(ReadRepoFile(ProviderRelativePath)),
            "string FixUsernameWithDomain(");

        // Non-UPN identity types return the username unchanged before anything
        // else runs.
        var earlyReturnAt = body.IndexOf(
            "if (_idType != IdentityType.UserPrincipalName) return username;",
            StringComparison.Ordinal);
        Assert.True(
            earlyReturnAt >= 0,
            "FixUsernameWithDomain no longer returns early, unchanged, for non-UserPrincipalName " +
            "identity types. DistinguishedName/Guid/Sid/SamAccountName lookups must not be routed " +
            "through qualifier validation meant for a UPN.");

        // The UPN path delegates to the shared helper, after the early return.
        var qualifierAt = body.IndexOf("UsernameQualifier.Resolve(", StringComparison.Ordinal);
        Assert.True(
            qualifierAt > earlyReturnAt,
            "FixUsernameWithDomain no longer routes the UserPrincipalName path through the shared " +
            "UsernameQualifier. Without it, a mismatched domain qualifier or a control character in " +
            "the submitted username reaches FindByIdentity unexamined.");

        // Rejections on this path use the AD provider's own credential-rejection
        // message, not the LDAP provider's "Invalid username format" — so a
        // rejected UPN stays indistinguishable from every other credential
        // failure this provider produces.
        Assert.Contains("DirectoryErrorTranslator.InvalidCredentialsMessage", body, StringComparison.Ordinal);

        // Checked against the RAW source, not the skeleton: CodeSkeleton blanks
        // every string literal to "" before extraction, so "Invalid username
        // format" can never appear in a skeleton-derived body regardless of
        // what the source actually contains -- that check would pass even if
        // the literal were reintroduced.
        var rawBody = ExtractMethodBody(
            ReadRepoFile(ProviderRelativePath),
            "string FixUsernameWithDomain(");
        Assert.DoesNotContain("Invalid username format", rawBody, StringComparison.Ordinal);
    }

    /// <summary>
    /// <c>ResolveMembershipAsync</c> -- the group-membership path, not the
    /// password-change path -- must route its identity through
    /// <c>FixUsernameWithDomain</c> too, so it inherits the same domain
    /// qualification and (new) rejection rules rather than handing a raw
    /// username straight to <c>FindByIdentity</c>. Without this, a mismatched
    /// or control-character-bearing qualifier would be rejected on the
    /// password-change path but silently accepted (and presumably resolve to
    /// "no such user") on the group-membership path -- an inconsistency
    /// nothing else in this suite would catch, since the provider cannot be
    /// exercised off Windows.
    /// </summary>
    [Fact]
    public void ResolveMembershipAsync_RoutesTheUsernameThroughFixUsernameWithDomain()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));
        var resolveBody = ExtractMethodBody(code, "Task<IResolvedGroupMembership> ResolveMembershipAsync(");

        Assert.Contains("FixUsernameWithDomain(username)", resolveBody, StringComparison.Ordinal);
    }

    /// <summary>
    /// <c>UsernameQualifier.Resolve</c> validates only the qualifier (see its
    /// own remarks) -- the local part is left to each provider. The AD
    /// provider's UPN path now depends on its own narrower check for it: a
    /// control character in the local part must be rejected the same way a
    /// bad qualifier is, rather than reaching <c>FindByIdentity</c>
    /// unexamined. A control-character check cannot reject ',' or '=', so this
    /// is safe to add without reopening the <c>DistinguishedName</c> concern
    /// that keeps the fuller <c>sAMAccountName</c> rules in the LDAP provider.
    /// </summary>
    [Fact]
    public void AdProvider_FixUsernameWithDomain_RejectsAControlCharacterInTheLocalPart()
    {
        var body = ExtractMethodBody(
            CodeSkeleton(ReadRepoFile(ProviderRelativePath)),
            "string FixUsernameWithDomain(");

        Assert.Contains("qualified.LocalPart", body, StringComparison.Ordinal);
        Assert.Contains("IsControl", body, StringComparison.Ordinal);
        Assert.Contains("DirectoryErrorTranslator.InvalidCredentialsMessage", body, StringComparison.Ordinal);
    }

    [Fact]
    public void AdProvider_DefaultLdapPortIs389()
    {
        var optionsContent = ReadRepoFile(OptionsRelativePath);
        Assert.Contains("public int LdapPort { get; set; } = 389;", optionsContent, StringComparison.Ordinal);
    }

    /// <summary>
    /// The alias table (DistinguishedName/Guid/Name/SamAccountName/Sid/UserPrincipalName and
    /// their aliases) moved into <c>UserIdentityTypeClassifier</c> so it can be exercised
    /// cross-platform. <c>SetIdType</c> must call the shared classifier and only map its
    /// result onto the Windows-only <c>IdentityType</c>, rather than carrying its own switch
    /// over string aliases.
    /// </summary>
    [Fact]
    public void AdProvider_SetIdTypeDelegatesToTheSharedClassifier()
    {
        var providerContent = ReadRepoFile(ProviderRelativePath);
        var body = ExtractMethodBody(CodeSkeleton(providerContent), "void SetIdType(");

        Assert.Contains(
            "UserIdentityTypeClassifier.Classify(",
            body,
            StringComparison.Ordinal);

        // No local alias switch left behind: these string literals belonged to the
        // old inline mapping and must not still be tested against the raw input here.
        Assert.DoesNotContain("distinguishedname", body, StringComparison.Ordinal);
        Assert.DoesNotContain("globallyuniqueidentifier", body, StringComparison.Ordinal);
        Assert.DoesNotContain("samaccountname", body, StringComparison.Ordinal);
        Assert.DoesNotContain("securityidentifier", body, StringComparison.Ordinal);
    }

    /// <summary>
    /// Warn only, per the deprecated-key precedent (EventId 101, LDAP provider):
    /// an unrecognized IdTypeForUser or one that cannot work from the web interface
    /// must not fail startup, and the "blank means default" case must not warn at all.
    /// </summary>
    [Fact]
    public void AdProvider_SetIdTypeWarnsOnUnrecognizedOrNotWebUsableIdentityTypes()
    {
        var providerContent = ReadRepoFile(ProviderRelativePath);
        var code = CodeSkeleton(providerContent);
        var body = ExtractMethodBody(code, "void SetIdType(");

        Assert.Contains("if (!recognized)", body, StringComparison.Ordinal);
        Assert.Contains("LogUnrecognizedIdentityType(Logger,", body, StringComparison.Ordinal);

        Assert.Contains("if (!usableInWebInterface)", body, StringComparison.Ordinal);
        Assert.Contains("LogIdentityTypeNotWebUsable(Logger,", body, StringComparison.Ordinal);

        // Both new EventIds are allocated, at Warning, and neither reuses or
        // renumbers an existing one.
        var unrecognizedDeclaration = code[code.IndexOf("LogUnrecognizedIdentityType =", StringComparison.Ordinal)..];
        Assert.Contains("LogLevel.Warning", unrecognizedDeclaration[..200], StringComparison.Ordinal);
        Assert.Contains("EventId(120", unrecognizedDeclaration[..300], StringComparison.Ordinal);

        var notWebUsableDeclaration = code[code.IndexOf("LogIdentityTypeNotWebUsable =", StringComparison.Ordinal)..];
        Assert.Contains("LogLevel.Warning", notWebUsableDeclaration[..200], StringComparison.Ordinal);
        Assert.Contains("EventId(121", notWebUsableDeclaration[..300], StringComparison.Ordinal);
    }

    /// <summary>
    /// Pins the divergence this batch fixed: an unresolvable user must report
    /// the same condition the LDAP provider's <c>FindUser</c> reports for it —
    /// <c>UserNotFoundException</c> via <c>DirectoryErrorTranslator.CreateUserNotFoundError</c>
    /// — rather than resolving to an empty membership set. Returning an empty
    /// set instead let <c>GroupMembershipPolicy</c> read an unknown user as
    /// "not in AllowedAdGroups" and report <c>ChangeNotPermitted</c> (6), where
    /// the LDAP provider reports <c>UserNotFound</c> (3) in Informative mode.
    /// Nothing else in this suite fails if that reinstates, since the provider
    /// cannot be exercised off Windows — this audit is what would catch it.
    /// </summary>
    [Fact]
    public void ResolveMembershipAsync_UnresolvableUser_ReportsUserNotFoundNotAnEmptySet()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));
        var resolveBody = ExtractMethodBody(code, "Task<IResolvedGroupMembership> ResolveMembershipAsync(");

        Assert.Contains(
            "throw DirectoryErrorTranslator.CreateUserNotFoundError(",
            resolveBody,
            StringComparison.Ordinal);

        // Comments are stripped by CodeSkeleton before this check, so a comment
        // explaining why the old value is gone cannot mask a real
        // reintroduction of it.
        Assert.DoesNotContain("NoSuchUser", code, StringComparison.Ordinal);
    }

    /// <summary>
    /// Guards the AD provider's <c>ServiceAccountHost()</c> override against
    /// being deleted as an apparent duplicate of the base default. It is not
    /// one: in automatic-context mode <c>Settings.LdapHostnames</c> is empty,
    /// so the base's "join every configured host" default would render as
    /// "n/a" in every <c>ServiceAccountFailure.Log</c> line for a mode most
    /// deployments run in. Deleting the override would compile cleanly and the
    /// diagnostics would just silently degrade.
    /// </summary>
    [Fact]
    public void ServiceAccountHost_OverrideNamesAutomaticDomainContext()
    {
        // Read raw (not CodeSkeleton) so the string literal content itself is
        // visible: CodeSkeleton blanks string literals to guard other checks
        // against being fooled by prose, which would blank this one too.
        var body = ExtractMethodBody(ReadRepoFile(ProviderRelativePath), "string ServiceAccountHost(");

        Assert.Contains("automatic domain context", body, StringComparison.Ordinal);
    }

    /// <summary>
    /// Pins the override that was silently lost once during consolidation:
    /// <c>AdministrativeResetSupported => !_options.UseAutomaticContext</c>. In
    /// automatic-context mode there is no service account bound with which to
    /// perform an administrative reset, so without this override the AD
    /// provider inherits the base's <c>=&gt; true</c> default and, with
    /// <c>AllowAdministrativeReset=true</c> AND <c>UseAutomaticContext=true</c>,
    /// a flagged account reaches the reset path with <c>BindForWrite</c>
    /// returning <see langword="null"/> and <c>userPrincipal.SetPassword(...)</c>
    /// executing as the process identity — bypassing password history and
    /// minimum-age policy in exactly the configuration EventId 103
    /// (<c>LogAdminResetIgnoredInAutomaticContext</c>) tells operators at
    /// startup is ignored.
    ///
    /// <para>The AD provider cannot be constructed or exercised off Windows
    /// (see the class summary), so a runtime test cannot pin this the way
    /// <c>LdapAdministrativeResetTests.AdministrativeResetSupported_TracksLdapChangePasswordWithDelAdd</c>
    /// pins the LDAP provider's equivalent override. A source audit is the
    /// only guard available here, and it exists specifically because this
    /// exact line was dropped once, silently, and every other test in this
    /// suite kept passing.</para>
    /// </summary>
    [Fact]
    public void AdProvider_HasAdministrativeResetSupportedOverrideGuardedOnUseAutomaticContext()
    {
        var code = CodeSkeleton(ReadRepoFile(ProviderRelativePath));

        var declarationAt = code.IndexOf("AdministrativeResetSupported", StringComparison.Ordinal);
        Assert.True(
            declarationAt >= 0,
            "PasswordChangeProvider no longer overrides AdministrativeResetSupported. Without it, " +
            "the base's '=> true' default lets automatic-context deployments reach the " +
            "administrative-reset fallback with no service account to reset with, so the write " +
            "runs as the process identity and bypasses password history/minimum-age policy.");

        var statementEnd = code.IndexOf(';', declarationAt);
        Assert.True(statementEnd > declarationAt, "Could not find the end of the AdministrativeResetSupported declaration.");

        var declaration = code[declarationAt..(statementEnd + 1)];

        Assert.Contains(
            "!_options.UseAutomaticContext",
            declaration.Replace(" ", string.Empty, StringComparison.Ordinal),
            StringComparison.Ordinal);
    }

    [Fact]
    public void WebStartup_EagerlyResolvesPasswordChangeProvider()
    {
        var programPath = "src/Unosquare.PassCore.Web/Program.cs";
        var programContent = ReadRepoFile(programPath);
        Assert.Contains("app.Services.GetRequiredService<IPasswordChangeProvider>()", programContent, StringComparison.Ordinal);
    }
}
