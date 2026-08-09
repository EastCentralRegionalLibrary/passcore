using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Unosquare.PassCore.Common;
using Xunit;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// The membership contract both directory providers now share.
/// </summary>
/// <remarks>
/// These replace three source-text audits over the AD provider
/// (<c>GroupMembership_FailsClosedWhenMembershipCannotBeDetermined</c>,
/// <c>..._CompletedEnumerationWithNoMatchIsADefinitiveNonMember</c> and
/// <c>..._ResolvesTheUserOncePerRequestRatherThanPerGroup</c>), which asserted the
/// invariant by matching that provider's source. The behaviour is now in
/// <see cref="ResolvedGroupMembership"/>, so it can be executed instead of read, and
/// what is proven here holds for every provider rather than the one whose file was
/// scanned.
/// </remarks>
public class ResolvedGroupMembershipTests
{
    private static readonly string[] Groups = { "Domain Admins" };

    private static ResolvedGroupMembership Resolution(
        GroupMembershipAnswer answer, Func<Exception, Exception>? translate = null) =>
        new(_ => Task.FromResult(answer),
            translate ?? (ex => new InvalidOperationException("translated", ex)));

    // ---------------------------------------------------------------
    // The three outcomes
    // ---------------------------------------------------------------

    [Fact]
    public async Task Member_IsTrue()
    {
        var resolution = Resolution(GroupMembershipAnswer.Member);

        Assert.True(await resolution.IsMemberOfAnyAsync(Groups));
    }

    [Fact]
    public async Task NotMember_IsFalse()
    {
        var resolution = Resolution(GroupMembershipAnswer.NotMember);

        Assert.False(await resolution.IsMemberOfAnyAsync(Groups));
    }

    /// <summary>
    /// The reason this type exists. A membership that could not be determined must
    /// never be answered as "not a member": <c>GroupMembershipPolicy</c> reads a
    /// negative for the restricted groups as permission to proceed, so answering
    /// false here would let a restricted account through during a partial directory
    /// failure.
    /// </summary>
    [Fact]
    public async Task Undetermined_ThrowsRatherThanAnsweringFalse()
    {
        var cause = new TimeoutException("enumeration failed");
        var resolution = Resolution(GroupMembershipAnswer.Undetermined(cause));

        var thrown = await Assert.ThrowsAsync<InvalidOperationException>(
            () => resolution.IsMemberOfAnyAsync(Groups));

        Assert.Same(cause, thrown.InnerException);
    }

    [Fact]
    public async Task Undetermined_PassesTheOriginalFailureToTheTranslator()
    {
        var cause = new TimeoutException("enumeration failed");
        Exception? seen = null;

        var resolution = Resolution(
            GroupMembershipAnswer.Undetermined(cause),
            ex =>
            {
                seen = ex;
                return new InvalidOperationException("translated", ex);
            });

        await Assert.ThrowsAsync<InvalidOperationException>(
            () => resolution.IsMemberOfAnyAsync(Groups));

        Assert.Same(cause, seen);
    }

    // ---------------------------------------------------------------
    // Structural guarantees
    // ---------------------------------------------------------------

    /// <summary>
    /// An undetermined answer cannot be constructed without the failure that caused
    /// it, which is what stops a provider reporting one it has already discarded.
    /// </summary>
    [Fact]
    public void Undetermined_RequiresAReason() =>
        Assert.Throws<ArgumentNullException>(() => GroupMembershipAnswer.Undetermined(null!));

    /// <summary>
    /// The definitive answers carry no failure. There is deliberately no way to build
    /// a <see cref="GroupMembershipState.NotMember"/> that holds one, so a caught
    /// exception cannot be reported as "determined not to be a member".
    /// </summary>
    [Fact]
    public void DefinitiveAnswers_CarryNoReason()
    {
        Assert.Equal(GroupMembershipState.Member, GroupMembershipAnswer.Member.State);
        Assert.Null(GroupMembershipAnswer.Member.Reason);

        Assert.Equal(GroupMembershipState.NotMember, GroupMembershipAnswer.NotMember.State);
        Assert.Null(GroupMembershipAnswer.NotMember.Reason);
    }

    [Fact]
    public void Undetermined_CarriesItsReason()
    {
        var cause = new TimeoutException();
        var answer = GroupMembershipAnswer.Undetermined(cause);

        Assert.Equal(GroupMembershipState.Undetermined, answer.State);
        Assert.Same(cause, answer.Reason);
    }

    // ---------------------------------------------------------------
    // No names to test
    // ---------------------------------------------------------------

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task NoGroupNames_IsFalseAndCostsNoEvaluation(bool useNull)
    {
        var evaluated = false;
        var resolution = new ResolvedGroupMembership(
            _ =>
            {
                evaluated = true;
                return Task.FromResult(GroupMembershipAnswer.Member);
            },
            ex => ex);

        var groupNames = useNull ? null! : Array.Empty<string>();

        Assert.False(await resolution.IsMemberOfAnyAsync(groupNames));
        Assert.False(evaluated);
    }

    /// <summary>
    /// An empty set cannot be undetermined, so it must not consult the evaluation at
    /// all — otherwise a directory outage would fail a request that asked nothing.
    /// </summary>
    [Fact]
    public async Task NoGroupNames_IsFalseEvenWhenTheEvaluationWouldBeUndetermined()
    {
        var resolution = Resolution(GroupMembershipAnswer.Undetermined(new TimeoutException()));

        Assert.False(await resolution.IsMemberOfAnyAsync(Array.Empty<string>()));
    }

    // ---------------------------------------------------------------
    // Resolve once, answer many
    // ---------------------------------------------------------------

    /// <summary>
    /// The resolution is handed one evaluation delegate and reuses it, which is what
    /// lets a provider resolve the user once per request and answer every configured
    /// group name from that single resolution.
    /// </summary>
    [Fact]
    public async Task EvaluationReceivesEachRequestedSet()
    {
        var seen = new List<IReadOnlyCollection<string>>();
        var resolution = new ResolvedGroupMembership(
            requested =>
            {
                seen.Add(requested);
                return Task.FromResult(GroupMembershipAnswer.NotMember);
            },
            ex => ex);

        await resolution.IsMemberOfAnyAsync(new[] { "Restricted" });
        await resolution.IsMemberOfAnyAsync(new[] { "Allowed", "Other" });

        Assert.Equal(2, seen.Count);
        Assert.Equal(new[] { "Restricted" }, seen[0]);
        Assert.Equal(new[] { "Allowed", "Other" }, seen[1]);
    }

    // ---------------------------------------------------------------
    // Guards
    // ---------------------------------------------------------------

    [Fact]
    public void Constructor_RequiresBothDelegates()
    {
        Assert.Throws<ArgumentNullException>(() =>
            new ResolvedGroupMembership(null!, ex => ex));

        Assert.Throws<ArgumentNullException>(() =>
            new ResolvedGroupMembership(_ => Task.FromResult(GroupMembershipAnswer.Member), null!));
    }
}
