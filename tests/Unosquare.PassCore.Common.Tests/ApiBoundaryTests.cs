using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Unosquare.PassCore.Common.Models;
using Unosquare.PassCore.Web.Controllers;
using Unosquare.PassCore.Web.Models;
using Xunit;

namespace Unosquare.PassCore.Common.Tests;

public class ApiBoundaryTests
{
    private static bool ValidateModel(object model, out List<ValidationResult> results)
    {
        var context = new ValidationContext(model, serviceProvider: null, items: null);
        results = new List<ValidationResult>();
        return Validator.TryValidateObject(model, context, results, validateAllProperties: true);
    }

    [Fact]
    public void ChangePasswordModel_ValidAtMaxLengths_PassesValidation()
    {
        var model = new ChangePasswordModel
        {
            Username = new string('u', ChangePasswordModel.MaxUsernameLength),
            CurrentPassword = new string('p', ChangePasswordModel.MaxPasswordLength),
            NewPassword = new string('n', ChangePasswordModel.MaxPasswordLength),
            NewPasswordVerify = new string('n', ChangePasswordModel.MaxPasswordLength),
            Recaptcha = new string('r', ChangePasswordModel.MaxRecaptchaLength),
        };

        var isValid = ValidateModel(model, out var results);

        Assert.True(isValid, $"Expected valid model but got errors: {string.Join(", ", results)}");
    }

    [Theory]
    [InlineData("Username", ChangePasswordModel.MaxUsernameLength + 1)]
    [InlineData("CurrentPassword", ChangePasswordModel.MaxPasswordLength + 1)]
    [InlineData("NewPassword", ChangePasswordModel.MaxPasswordLength + 1)]
    [InlineData("NewPasswordVerify", ChangePasswordModel.MaxPasswordLength + 1)]
    [InlineData("Recaptcha", ChangePasswordModel.MaxRecaptchaLength + 1)]
    public void ChangePasswordModel_OneCharOverMax_FailsValidation(string fieldName, int length)
    {
        var model = new ChangePasswordModel
        {
            Username = fieldName == "Username" ? new string('a', length) : "validUser",
            CurrentPassword = fieldName == "CurrentPassword" ? new string('b', length) : "validCurrentPassword",
            NewPassword = fieldName == "NewPassword" ? new string('c', length) : "validNewPassword123!",
            NewPasswordVerify = fieldName is "NewPassword" or "NewPasswordVerify" ? new string('c', length) : "validNewPassword123!",
            Recaptcha = fieldName == "Recaptcha" ? new string('r', length) : "validToken",
        };

        var isValid = ValidateModel(model, out var results);

        Assert.False(isValid);
        Assert.Contains(results, r => r.MemberNames.Contains(fieldName));
    }

    [Theory]
    [InlineData("Username", ChangePasswordModel.MaxUsernameLength + 1)]
    [InlineData("CurrentPassword", ChangePasswordModel.MaxPasswordLength + 1)]
    [InlineData("NewPassword", ChangePasswordModel.MaxPasswordLength + 1)]
    [InlineData("NewPasswordVerify", ChangePasswordModel.MaxPasswordLength + 1)]
    [InlineData("Recaptcha", ChangePasswordModel.MaxRecaptchaLength + 1)]
    public async Task ControllerPost_OversizedRequest_ReturnsBadRequestAndNeverInvokesProvider(string fieldName, int length)
    {
        var mockProvider = new Mock<IPasswordChangeProvider>();
        var mockHttpClientFactory = new Mock<IHttpClientFactory>();
        var options = Options.Create(new ClientSettings());

        var controller = new PasswordController(
            NullLogger<PasswordController>.Instance,
            options,
            mockProvider.Object,
            mockHttpClientFactory.Object);

        var model = new ChangePasswordModel
        {
            Username = fieldName == "Username" ? new string('a', length) : "validUser",
            CurrentPassword = fieldName == "CurrentPassword" ? new string('b', length) : "validCurrentPassword",
            NewPassword = fieldName == "NewPassword" ? new string('c', length) : "validNewPassword123!",
            NewPasswordVerify = fieldName is "NewPassword" or "NewPasswordVerify" ? new string('c', length) : "validNewPassword123!",
            Recaptcha = fieldName == "Recaptcha" ? new string('r', length) : "validToken",
        };

        // Populate controller.ModelState with validation results
        ValidateModel(model, out var validationResults);
        foreach (var validationResult in validationResults)
        {
            foreach (var memberName in validationResult.MemberNames)
            {
                controller.ModelState.AddModelError(memberName, validationResult.ErrorMessage ?? "Invalid");
            }
        }

        var result = await controller.Post(model);

        var badRequestResult = Assert.IsType<BadRequestObjectResult>(result);
        Assert.Equal(StatusCodes.Status400BadRequest, badRequestResult.StatusCode);

        var apiResult = Assert.IsType<ApiResult>(badRequestResult.Value);
        Assert.NotEmpty(apiResult.Errors);

        // Prove the password change provider was never called
        mockProvider.Verify(
            p => p.PerformPasswordChangeAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<string>()),
            Times.Never);
    }
}
