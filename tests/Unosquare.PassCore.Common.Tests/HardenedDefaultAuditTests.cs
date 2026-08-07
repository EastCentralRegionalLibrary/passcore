using System;
using System.Collections.Generic;
using System.IO;
using Xunit;
using static Unosquare.PassCore.Testing.RepositorySource;

namespace Unosquare.PassCore.Common.Tests;

/// <summary>
/// Pins <c>Hardened</c> as the shipped default disclosure posture on the AD
/// side of the codebase: the <see cref="ErrorDisclosureMode"/> property
/// declared on <c>PasswordChangeOptions</c> (the AD provider's options class),
/// and the value shipped in <c>src/Unosquare.PassCore.Web/appsettings.json</c>.
///
/// <para><b>Why this file and not an addition to an existing one.</b>
/// <c>AdProviderDirectoryWriteAuditTests</c> already reads both of these files
/// for unrelated properties, but folding this assertion into it (or into the
/// LDAP-side <c>ShippedConfigurationUsernameFormTests</c>) would put it in the
/// same file another change is independently touching. Keeping it here keeps
/// the two changes' file sets disjoint.</para>
///
/// <para><b>What this guards, and what it does not.</b> Hardened collapses
/// every credential and account-state condition into one indistinguishable
/// response, denying an attacker an account-existence oracle; Informative
/// trades that away for operator/user-friendly detail. Both are legitimate
/// choices for an operator to make deliberately in their own deployment's
/// configuration. What must not happen is the shipped default silently
/// becoming Informative — in the class declaration, where every deployment
/// that does not override it inherits the value, or in the sample
/// configuration file operators copy from. If the default is ever
/// deliberately changed, these assertions must be re-derived against the new
/// value, not deleted — see the parallel note on
/// <c>ShippedConfigurationUsernameFormTests.ShippedConfiguration_AsksForAnEmailAddressAndConfiguresNoDefaultDomain</c>.</para>
/// </summary>
public class HardenedDefaultAuditTests
{
    private const string OptionsRelativePath =
        "src/Unosquare.PassCore.PasswordProvider/PasswordChangeOptions.cs";

    private const string AppSettingsRelativePath =
        "src/Unosquare.PassCore.Web/appsettings.json";

    [Fact]
    public void PasswordChangeOptions_DeclaresHardenedAsTheErrorDisclosureModeDefault()
    {
        var content = ReadRepoFile(OptionsRelativePath);

        Assert.Contains(
            "public ErrorDisclosureMode ErrorDisclosureMode { get; set; } = ErrorDisclosureMode.Hardened;",
            content,
            StringComparison.Ordinal);
        // If this assertion is failing because the default was deliberately
        // changed to Informative, re-derive this test against the new value —
        // do not delete it. Hardened is the target posture: it denies an
        // attacker an account-existence oracle, and the shipped default is
        // what every deployment that does not override it inherits.
    }

    [Fact]
    public void ShippedAppSettings_CarriesHardenedAsTheErrorDisclosureModeValue()
    {
        var content = ReadRepoFile(AppSettingsRelativePath);

        Assert.Contains(
            "\"ErrorDisclosureMode\": \"Hardened\"",
            content,
            StringComparison.Ordinal);
        // Same caveat as above: if the shipped sample configuration is ever
        // deliberately changed to "Informative", re-derive this test against
        // the new value rather than deleting it. Hardened is the target
        // posture for the configuration operators copy from.
    }

}
