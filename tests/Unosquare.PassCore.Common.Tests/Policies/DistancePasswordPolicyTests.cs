using System;
using System.Threading.Tasks;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Exceptions;
using Unosquare.PassCore.Common.Models;
using Unosquare.PassCore.Common.Policies;
using Xunit;

namespace Unosquare.PassCore.Common.Tests.Policies;

public class DistancePasswordPolicyTests
{
    [Fact]
    public async Task ValidateAsync_MinimumDistanceZero_AlwaysPasses()
    {
        var policy = new DistancePasswordPolicy();
        var settings = new ClientSettings { MinimumDistance = 0 };
        var context = new PasswordChangeContext("u", "same", "same", settings);

        await policy.ValidateAsync(context, provider: null!);
    }

    [Fact]
    public async Task ValidateAsync_PasswordsTooSimilar_Throws()
    {
        var policy = new DistancePasswordPolicy();
        var settings = new ClientSettings { MinimumDistance = 5 };
        var context = new PasswordChangeContext("u", "password1", "password2", settings);

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => policy.ValidateAsync(context, provider: null!));

        Assert.Equal(ApiErrorCode.MinimumDistance, ex.ErrorCode);
    }

    [Fact]
    public async Task ValidateAsync_SufficientlyDifferentPasswords_Passes()
    {
        var policy = new DistancePasswordPolicy();
        var settings = new ClientSettings { MinimumDistance = 5 };
        var context = new PasswordChangeContext("u", "oldsecret", "TotallyDifferent!42", settings);

        await policy.ValidateAsync(context, provider: null!);
    }

    [Fact]
    public async Task ValidateAsync_EmptyOldPassword_DistanceEqualsNewPasswordLength()
    {
        var policy = new DistancePasswordPolicy();
        var settings = new ClientSettings { MinimumDistance = 5 };
        var context = new PasswordChangeContext("u", string.Empty, "abc", settings);

        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => policy.ValidateAsync(context, provider: null!));

        Assert.Equal(ApiErrorCode.MinimumDistance, ex.ErrorCode);
    }

    [Fact]
    public void MeasureNewPasswordDistance_IdenticalStrings_ReturnsZero()
    {
        var distance = DistancePasswordPolicy.MeasureNewPasswordDistance("secret123", "secret123");
        Assert.Equal(0, distance);
    }

    [Fact]
    public void MeasureNewPasswordDistance_SingleInsertion_ReturnsOne()
    {
        var distance = DistancePasswordPolicy.MeasureNewPasswordDistance("abc", "abcd");
        Assert.Equal(1, distance);
    }

    [Fact]
    public void MeasureNewPasswordDistance_SingleDeletion_ReturnsOne()
    {
        var distance = DistancePasswordPolicy.MeasureNewPasswordDistance("abcd", "abc");
        Assert.Equal(1, distance);
    }

    [Fact]
    public void MeasureNewPasswordDistance_SingleSubstitution_ReturnsOne()
    {
        var distance = DistancePasswordPolicy.MeasureNewPasswordDistance("abc", "adc");
        Assert.Equal(1, distance);
    }

    [Fact]
    public void MeasureNewPasswordDistance_MultipleEdits_ReturnsCorrectDistance()
    {
        var distance = DistancePasswordPolicy.MeasureNewPasswordDistance("kitten", "sitting");
        Assert.Equal(3, distance);
    }

    [Theory]
    [InlineData("", "", 0)]
    [InlineData("", "hello", 5)]
    [InlineData("hello", "", 5)]
    public void MeasureNewPasswordDistance_EmptyStrings_ReturnsLengthOfOtherString(string s1, string s2, int expected)
    {
        var distance = DistancePasswordPolicy.MeasureNewPasswordDistance(s1, s2);
        Assert.Equal(expected, distance);
    }

    [Theory]
    [InlineData(2, 1, false)] // distance 1 < MinimumDistance 2 -> reject (throws)
    [InlineData(1, 1, true)]  // distance 1 == MinimumDistance 1 -> accept (passes)
    [InlineData(1, 2, true)]  // distance 1 > MinimumDistance 0 -> accept (passes)
    public async Task ValidateAsync_ExactThresholdBoundary_BehavesCorrectly(int minimumDistance, int actualEdits, bool shouldPass)
    {
        var policy = new DistancePasswordPolicy();
        var settings = new ClientSettings { MinimumDistance = minimumDistance };

        // "abc" vs "adc" has distance 1
        // "abc" vs "a" has distance 2
        var newPassword = actualEdits == 1 ? "adc" : "a";
        var context = new PasswordChangeContext("u", "abc", newPassword, settings);

        if (shouldPass)
        {
            await policy.ValidateAsync(context, provider: null!);
        }
        else
        {
            var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
                () => policy.ValidateAsync(context, provider: null!));
            Assert.Equal(ApiErrorCode.MinimumDistance, ex.ErrorCode);
        }
    }

    [Fact]
    public void MeasureNewPasswordDistance_LengthDifferenceExceedsThreshold_ShortCircuits()
    {
        const int threshold = 5;
        var s1 = "a";
        var s2 = new string('x', 20);

        var distance = DistancePasswordPolicy.MeasureNewPasswordDistance(s1, s2, threshold);
        Assert.True(distance >= threshold);
        Assert.Equal(19, distance);
    }

    [Fact]
    public async Task ValidateAsync_ResourceRegression_LargeStringsLinearExecution()
    {
        var policy = new DistancePasswordPolicy();
        var settings = new ClientSettings { MinimumDistance = 100 };

        var currentPassword = new string('A', 1000);
        var newPassword = new string('A', 1000) + "XYZ"; // distance 3

        var context = new PasswordChangeContext("u", currentPassword, newPassword, settings);

        // Should be rejected quickly because edit distance 3 < MinimumDistance 100
        var ex = await Assert.ThrowsAsync<PasswordPolicyViolationException>(
            () => policy.ValidateAsync(context, provider: null!));

        Assert.Equal(ApiErrorCode.MinimumDistance, ex.ErrorCode);

        // Now test with length difference >= threshold
        var newPasswordLong = new string('A', 1000) + new string('B', 150); // diff 150 >= 100
        var contextPass = new PasswordChangeContext("u", currentPassword, newPasswordLong, settings);

        await policy.ValidateAsync(contextPass, provider: null!);
    }
}
