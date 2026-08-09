using System;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace Unosquare.PassCore.Common;

/// <summary>
/// The three outcomes a group-membership evaluation can have.
/// </summary>
/// <remarks>
/// The third state is the point of the type. A membership check that could not be
/// completed is not the same as one that completed and found nothing, and collapsing
/// the two is a deny-list hole: <c>GroupMembershipPolicy</c> reads a negative answer
/// for the restricted groups as "safe to proceed", so a failed enumeration reported
/// as <see cref="NotMember"/> would let a restricted account through.
/// </remarks>
public enum GroupMembershipState
{
    /// <summary>The user belongs to at least one of the tested groups.</summary>
    Member,

    /// <summary>
    /// Every lookup that could have matched ran, and none did. This is a definitive
    /// negative, safe for a caller to act on.
    /// </summary>
    NotMember,

    /// <summary>
    /// At least one lookup that could still have matched did not complete, so no
    /// negative answer can be given. Carries the failure that caused it.
    /// </summary>
    Undetermined,
}

/// <summary>
/// The result of testing a resolved user against a set of group names.
/// </summary>
/// <remarks>
/// <para>Both directory providers used to hand-roll this distinction with a local
/// <c>Exception? undetermined</c> and their own decision about what a negative answer
/// meant, each guarded only by a source-text audit. This type makes the invariant
/// structural instead: <see cref="NotMember"/> takes no failure and
/// <see cref="Undetermined"/> requires one, so a provider cannot report "not a member"
/// while holding a failure without visibly discarding it.</para>
/// <para>Turning <see cref="GroupMembershipState.Undetermined"/> into a thrown
/// exception is deliberately NOT done here. It happens in exactly one place —
/// <see cref="ResolvedGroupMembership"/> — so that neither provider, and no future
/// provider, can translate it differently or forget to.</para>
/// </remarks>
public readonly struct GroupMembershipAnswer : IEquatable<GroupMembershipAnswer>
{
    private GroupMembershipAnswer(GroupMembershipState state, Exception? reason)
    {
        State = state;
        Reason = reason;
    }

    /// <summary>The outcome of the evaluation.</summary>
    public GroupMembershipState State { get; }

    /// <summary>
    /// Why the membership could not be determined. Non-<see langword="null"/> if and
    /// only if <see cref="State"/> is <see cref="GroupMembershipState.Undetermined"/>.
    /// </summary>
    public Exception? Reason { get; }

    /// <summary>A match was found. Definitive regardless of what else failed.</summary>
    public static GroupMembershipAnswer Member { get; } =
        new(GroupMembershipState.Member, null);

    /// <summary>
    /// Every lookup ran and none matched. Takes no failure, by design: if a lookup
    /// failed, the answer is <see cref="Undetermined"/>, not this.
    /// </summary>
    public static GroupMembershipAnswer NotMember { get; } =
        new(GroupMembershipState.NotMember, null);

    /// <summary>
    /// A lookup that could still have matched did not complete.
    /// </summary>
    /// <param name="reason">The failure. Required — an undetermined answer with no
    /// cause cannot be translated into a meaningful error for the caller.</param>
    public static GroupMembershipAnswer Undetermined(Exception reason)
    {
        ArgumentNullException.ThrowIfNull(reason);
        return new GroupMembershipAnswer(GroupMembershipState.Undetermined, reason);
    }

    /// <inheritdoc />
    public bool Equals(GroupMembershipAnswer other) =>
        State == other.State && ReferenceEquals(Reason, other.Reason);

    /// <inheritdoc />
    public override bool Equals(object? obj) =>
        obj is GroupMembershipAnswer other && Equals(other);

    /// <inheritdoc />
    public override int GetHashCode() => HashCode.Combine(State, Reason);

    /// <summary>Equality operator.</summary>
    public static bool operator ==(GroupMembershipAnswer left, GroupMembershipAnswer right) =>
        left.Equals(right);

    /// <summary>Inequality operator.</summary>
    public static bool operator !=(GroupMembershipAnswer left, GroupMembershipAnswer right) =>
        !left.Equals(right);
}

/// <summary>
/// The single place a <see cref="GroupMembershipAnswer"/> becomes the
/// <see cref="bool"/>-or-throw contract that <see cref="IResolvedGroupMembership"/>
/// presents to callers.
/// </summary>
/// <remarks>
/// <para>Providers supply only an evaluation delegate; they never implement
/// <see cref="IResolvedGroupMembership"/> themselves. That keeps the
/// undetermined-to-exception translation at one site shared by both, rather than
/// duplicated per provider where the two could drift — which is what the source-text
/// audits existed to detect.</para>
/// <para>The delegate shape also carries both providers' resolution models without
/// forcing either to change: the AD provider resolves eagerly and closes over a
/// materialized set of names, while the LDAP provider defers all directory work to
/// the first evaluation and caches the resolved user for later ones.</para>
/// </remarks>
public sealed class ResolvedGroupMembership : IResolvedGroupMembership
{
    private readonly Func<IReadOnlyCollection<string>, Task<GroupMembershipAnswer>> _evaluate;
    private readonly Func<Exception, Exception> _translate;

    /// <summary>
    /// Creates a resolution backed by <paramref name="evaluate"/>.
    /// </summary>
    /// <param name="evaluate">Tests the resolved user against a set of group names.</param>
    /// <param name="translate">Turns an undetermined answer's failure into the
    /// exception the caller sees. Supplied by the provider base so that it carries the
    /// service-account actor and the configured disclosure mode.</param>
    public ResolvedGroupMembership(
        Func<IReadOnlyCollection<string>, Task<GroupMembershipAnswer>> evaluate,
        Func<Exception, Exception> translate)
    {
        ArgumentNullException.ThrowIfNull(evaluate);
        ArgumentNullException.ThrowIfNull(translate);

        _evaluate = evaluate;
        _translate = translate;
    }

    /// <inheritdoc />
    public async Task<bool> IsMemberOfAnyAsync(IReadOnlyCollection<string> groupNames)
    {
        // No names to test cannot be undetermined, and must not cost a directory
        // round trip. Both providers short-circuited this themselves before.
        if (groupNames is null || groupNames.Count == 0)
            return false;

        var answer = await _evaluate(groupNames).ConfigureAwait(false);

        return answer.State switch
        {
            GroupMembershipState.Member => true,
            GroupMembershipState.NotMember => false,
            GroupMembershipState.Undetermined => throw _translate(
                answer.Reason ?? new InvalidOperationException(
                    "An undetermined group membership carried no reason.")),
            _ => throw new InvalidOperationException(
                $"Unhandled group membership state '{answer.State}'."),
        };
    }
}
