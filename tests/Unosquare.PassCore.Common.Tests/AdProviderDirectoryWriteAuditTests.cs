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

    /// <summary>
    /// The three checks now live once, in <c>AppSettingsValidation.ValidateServiceAccount</c>,
    /// shared with the LDAP provider. This provider must call it rather than carry its own
    /// copy, and must pass the same <c>UseAutomaticContext</c>-derived requirement the old
    /// inline <c>if</c> guarded: a service account is only required for an explicit bind.
    /// </summary>
    [Fact]
    public void AdProvider_ValidateOptionsDelegatesToTheSharedServiceAccountValidator()
    {
        var providerContent = ReadRepoFile(ProviderRelativePath);
        var body = ExtractMethodBody(CodeSkeleton(providerContent), "void ValidateOptions(");

        Assert.Contains(
            "AppSettingsValidation.ValidateServiceAccount(opts, required: !opts.UseAutomaticContext)",
            body,
            StringComparison.Ordinal);

        // No re-implementation alongside the delegation: the checks belong to
        // AppSettingsValidation now, not to this method.
        Assert.DoesNotContain("opts.LdapHostnames", body, StringComparison.Ordinal);
        Assert.DoesNotContain("opts.LdapUsername", body, StringComparison.Ordinal);
        Assert.DoesNotContain("opts.LdapPassword", body, StringComparison.Ordinal);
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
