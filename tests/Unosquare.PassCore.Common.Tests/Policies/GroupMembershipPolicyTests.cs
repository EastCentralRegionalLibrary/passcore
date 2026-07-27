using System.Collections.Generic;
using System.Threading.Tasks;
using Moq;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using Unosquare.PassCore.Common.Policies;
using Xunit;

namespace Unosquare.PassCore.Common.Tests.Policies;

public class GroupMembershipPolicyTests
{
    [Fact]
    public async Task ValidateAsync_ProviderDoesNotImplementTester_Passes()
    {
        var policy = new GroupMembershipPolicy();
        var provider = new Mock<IPasswordChangeProvider>();
        var settings = new ClientSettings
        {
            PasswordProviderOptions = new PasswordProviderOptions
            {
                RestrictedAdGroups = new List<string> { "ShouldBeIgnored" },
            },
        };
        var context = new PasswordChangeContext("u", "old", "new", settings);

        await policy.ValidateAsync(context, provider.Object);
    }

    [Fact]
    public async Task ValidateAsync_NoGroupsConfigured_Passes()
    {
        var policy = new GroupMembershipPolicy();
        var provider = MockTester(_ => false);
        var settings = new ClientSettings
        {
            PasswordProviderOptions = new PasswordProviderOptions(),
        };
        var context = new PasswordChangeContext("u", "old", "new", settings);

        await policy.ValidateAsync(context, provider);
    }

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public async Task ValidateAsync_UserInRestrictedGroup_Throws(ErrorDisclosureMode mode)
    {
        var policy = new GroupMembershipPolicy();
        var provider = MockTester(group => group == "Admins", mode);
        var settings = new ClientSettings
        {
            PasswordProviderOptions = new PasswordProviderOptions
            {
                RestrictedAdGroups = new List<string> { "Admins", "RootOps" },
            },
        };
        var context = new PasswordChangeContext("u", "old", "new", settings);

        if (mode == ErrorDisclosureMode.Hardened)
        {
            var ex = await Assert.ThrowsAsync<InvalidCredentialsException>(
                () => policy.ValidateAsync(context, provider));
            Assert.Equal(DirectoryErrorTranslator.InvalidCredentialsMessage, ex.Message);
        }
        else
        {
            var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
                () => policy.ValidateAsync(context, provider));
            Assert.Equal(ApiErrorCode.ChangeNotPermitted, ex.ErrorCode);
            Assert.Equal(DirectoryErrorTranslator.AccountStateMessage, ex.Message);
        }
    }

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public async Task ValidateAsync_UserNotInAllowedGroups_Throws(ErrorDisclosureMode mode)
    {
        var policy = new GroupMembershipPolicy();
        var provider = MockTester(_ => false, mode);
        var settings = new ClientSettings
        {
            PasswordProviderOptions = new PasswordProviderOptions
            {
                AllowedAdGroups = new List<string> { "PasswordResetUsers" },
            },
        };
        var context = new PasswordChangeContext("u", "old", "new", settings);

        if (mode == ErrorDisclosureMode.Hardened)
        {
            var ex = await Assert.ThrowsAsync<InvalidCredentialsException>(
                () => policy.ValidateAsync(context, provider));
            Assert.Equal(DirectoryErrorTranslator.InvalidCredentialsMessage, ex.Message);
        }
        else
        {
            var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
                () => policy.ValidateAsync(context, provider));
            Assert.Equal(ApiErrorCode.ChangeNotPermitted, ex.ErrorCode);
            Assert.Equal(DirectoryErrorTranslator.AccountStateMessage, ex.Message);
        }
    }

    [Fact]
    public async Task ValidateAsync_UserInAtLeastOneAllowedGroup_Passes()
    {
        var policy = new GroupMembershipPolicy();
        var provider = MockTester(group => group == "PasswordResetUsers");
        var settings = new ClientSettings
        {
            PasswordProviderOptions = new PasswordProviderOptions
            {
                AllowedAdGroups = new List<string> { "PasswordResetUsers", "OtherGroup" },
            },
        };
        var context = new PasswordChangeContext("u", "old", "new", settings);

        await policy.ValidateAsync(context, provider);
    }

    [Theory]
    [InlineData(ErrorDisclosureMode.Hardened)]
    [InlineData(ErrorDisclosureMode.Informative)]
    public async Task ValidateAsync_RestrictedIsCheckedBeforeAllowed(ErrorDisclosureMode mode)
    {
        var policy = new GroupMembershipPolicy();
        var provider = MockTester(group => group is "Admins" or "PasswordResetUsers", mode);
        var settings = new ClientSettings
        {
            PasswordProviderOptions = new PasswordProviderOptions
            {
                RestrictedAdGroups = new List<string> { "Admins" },
                AllowedAdGroups = new List<string> { "PasswordResetUsers" },
            },
        };
        var context = new PasswordChangeContext("u", "old", "new", settings);

        if (mode == ErrorDisclosureMode.Hardened)
        {
            var ex = await Assert.ThrowsAsync<InvalidCredentialsException>(
                () => policy.ValidateAsync(context, provider));
            Assert.Equal(DirectoryErrorTranslator.InvalidCredentialsMessage, ex.Message);
        }
        else
        {
            var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
                () => policy.ValidateAsync(context, provider));
            Assert.Equal(ApiErrorCode.ChangeNotPermitted, ex.ErrorCode);
            Assert.Equal(DirectoryErrorTranslator.AccountStateMessage, ex.Message);
        }
    }

    private static IPasswordChangeProvider MockTester(System.Func<string, bool> isMember, ErrorDisclosureMode disclosureMode = ErrorDisclosureMode.Hardened)
    {
        var mock = new Mock<IPasswordChangeProvider>();
        mock.As<IGroupMembershipTester>()
            .Setup(t => t.IsMemberOfGroupAsync(It.IsAny<string>(), It.IsAny<string>()))
            .Returns<string, string>((_, group) => Task.FromResult(isMember(group)));
        mock.As<IDisclosurePosture>()
            .Setup(p => p.ErrorDisclosureMode)
            .Returns(disclosureMode);
        return mock.Object;
    }
}
