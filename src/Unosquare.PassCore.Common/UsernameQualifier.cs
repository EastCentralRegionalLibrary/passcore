using System;
using System.Linq;
using Unosquare.PassCore.Common.Exceptions;

namespace Unosquare.PassCore.Common;

/// <summary>
/// The parsed result of <see cref="UsernameQualifier.Resolve"/>: the local
/// (account-name) part and the resolved domain qualifier, if any.
/// </summary>
/// <param name="LocalPart">The account-name portion, with any qualifier
/// separator removed. Never null; may be empty if the caller supplied an
/// empty string.</param>
/// <param name="DomainPart">The resolved domain qualifier, or
/// <see langword="null"/> when the username carries none and none was
/// supplied to qualify it with.</param>
public readonly record struct QualifiedUsername(string LocalPart, string? DomainPart);

/// <summary>
/// Provider-agnostic parsing, validation and canonicalization of a qualified
/// username (<c>DOMAIN\user</c> or <c>user@domain</c>) against a configured
/// <c>DefaultDomain</c>. Shared by the AD and LDAP providers so a mismatched
/// domain qualifier or a control character in the qualifier is rejected
/// identically by both, rather than only by the provider that happens to
/// build a filter string.
/// </summary>
/// <remarks>
/// <para>Deliberately excluded: RFC 4515 escaping and the LDAP
/// <c>sAMAccountName</c> character rules. Those are transport-specific — an
/// AD <c>DistinguishedName</c> identity legitimately contains characters
/// (<c>,</c>, <c>=</c>) that would be invalid in a <c>sAMAccountName</c>
/// filter — and stay with the provider that needs them.</para>
/// <para>A configured <c>defaultDomain</c> is authoritative: a bare name is
/// qualified with it, a qualifier that matches it (the domain itself or its
/// NetBIOS prefix) is canonicalized to it, and any other qualifier is
/// rejected. With no configured domain there is nothing to validate a
/// qualifier against, so a qualified name is accepted: a UPN suffix is kept
/// (meaningful on its own), while a NetBIOS qualifier is dropped (not a UPN
/// suffix, and there is no configured domain to map it onto).</para>
/// <para><b>Only the qualifier is validated here.</b> This method never
/// inspects <see cref="QualifiedUsername.LocalPart"/> — not for emptiness,
/// not for control characters, not against the LDAP
/// <c>InvalidAccountNameCharsRegex</c>. The LDAP provider validates its local
/// part itself, by design, because that is also where the transport-specific
/// <c>sAMAccountName</c> rules above live; the AD provider is responsible for
/// whatever local-part checks it needs on its own path. A caller must not
/// assume the two providers reject an ill-formed local part identically —
/// only a rejected qualifier is guaranteed to match between them.</para>
/// </remarks>
public static class UsernameQualifier
{
    /// <summary>
    /// Parses <paramref name="username"/> into a local part and a resolved
    /// domain part, validating any qualifier against
    /// <paramref name="defaultDomain"/>.
    /// </summary>
    /// <param name="username">The raw, caller-supplied username.</param>
    /// <param name="defaultDomain">The configured default domain, or
    /// <see langword="null"/>, empty, or whitespace-only when none is
    /// configured. A whitespace-only value is treated as unconfigured rather
    /// than as a literal domain to match against.</param>
    /// <param name="rejectionMessage">The message to use for every rejection,
    /// so a caller's rejections stay indistinguishable from one another.</param>
    /// <returns>The parsed local and domain parts.</returns>
    /// <exception cref="InvalidCredentialsException">
    /// The username carries both a NetBIOS and a UPN separator, the
    /// qualifier contains a control character, or a configured
    /// <paramref name="defaultDomain"/> is set and the qualifier does not
    /// match it.
    /// </exception>
    public static QualifiedUsername Resolve(string username, string? defaultDomain, string rejectionMessage)
    {
        ArgumentNullException.ThrowIfNull(username);
        ArgumentNullException.ThrowIfNull(rejectionMessage);

        // A whitespace-only value (e.g. a stray " " left in configuration) is
        // not a configured domain: nothing trims or validates DefaultDomain
        // before it reaches here, and treating it as authoritative would
        // reject every qualified username and mis-qualify every bare one.
        // IsNullOrEmpty alone (what this used to test) would leave that typo
        // silently authoritative.
        var effectiveDomain = string.IsNullOrWhiteSpace(defaultDomain) ? null : defaultDomain.Trim();

        var localPart = username;
        string? domainPart = null;
        var netbiosQualified = false;

        var backslashIndex = username.IndexOf('\\', StringComparison.Ordinal);
        var atIndex = username.IndexOf('@', StringComparison.Ordinal);

        // A username is qualified in one syntax or the other. Something
        // carrying both separators is well-formed in neither.
        if (backslashIndex >= 0 && atIndex >= 0)
            throw new InvalidCredentialsException(rejectionMessage);

        if (backslashIndex >= 0)
        {
            domainPart = username[..backslashIndex];
            localPart = username[(backslashIndex + 1)..];
            netbiosQualified = true;
        }
        else if (atIndex >= 0)
        {
            domainPart = username[(atIndex + 1)..];
            localPart = username[..atIndex];
        }

        // The supplied qualifier is user input reaching a directory call
        // (or, for LDAP, a filter that escapes it separately); a control
        // character in it is rejected outright.
        if (!string.IsNullOrEmpty(domainPart) && domainPart.Any(char.IsControl))
            throw new InvalidCredentialsException(rejectionMessage);

        if (effectiveDomain is null)
        {
            // Nothing is configured to validate the qualifier against, so it
            // is accepted: a UPN suffix is kept, a NetBIOS name is dropped.
            if (netbiosQualified)
                domainPart = null;
        }
        else
        {
            if (!string.IsNullOrEmpty(domainPart) && !IsDomainMatching(domainPart, effectiveDomain))
                throw new InvalidCredentialsException(rejectionMessage);

            // The configured domain is authoritative: it qualifies a bare
            // name and canonicalizes a matching NetBIOS prefix to the full
            // domain.
            domainPart = effectiveDomain;
        }

        return new QualifiedUsername(localPart, domainPart);
    }

    private static bool IsDomainMatching(string domainPart, string defaultDomain)
    {
        if (string.Equals(domainPart, defaultDomain, StringComparison.OrdinalIgnoreCase))
            return true;

        var dotIndex = defaultDomain.IndexOf('.', StringComparison.Ordinal);
        if (dotIndex > 0)
        {
            var prefix = defaultDomain[..dotIndex];
            if (string.Equals(domainPart, prefix, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
