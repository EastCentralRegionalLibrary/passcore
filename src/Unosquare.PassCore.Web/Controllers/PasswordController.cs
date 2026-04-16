using Unosquare.PassCore.Web.Helpers;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Unosquare.PassCore.Web.Models;
using System.Text.Json;
using System.Net.Http;
using Zxcvbn;

namespace Unosquare.PassCore.Web.Controllers;

/// <summary>
/// Represents a controller class holding all of the server-side functionality of this tool.
/// </summary>
[Route("api/[controller]")]
public class PasswordController : Controller
{
    private readonly ILogger _logger;
    private readonly ClientSettings _options;
    private readonly IPasswordChangeProvider _passwordChangeProvider;
    private readonly IHttpClientFactory _httpClientFactory;

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordController" /> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="optionsAccessor">The options accessor.</param>
    /// <param name="passwordChangeProvider">The password change provider.</param>
    public PasswordController(
        ILogger<PasswordController> logger,
        IOptions<ClientSettings> optionsAccessor,
        IPasswordChangeProvider passwordChangeProvider,
        IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _options = optionsAccessor.Value;
        _passwordChangeProvider = passwordChangeProvider;
        _httpClientFactory = httpClientFactory;
    }

    /// <summary>
    /// Returns the ClientSettings object as a JSON string.
    /// </summary>
    /// <returns>A Json representation of the ClientSettings object.</returns>
    [HttpGet]
    public IActionResult Get() => Json(_options);

    /// <summary>
    /// Returns generated password as a JSON string.
    /// </summary>
    /// <returns>A Json with a password property which contains a random generated password.</returns>
    [HttpGet]
    [Route("generated")]
    public IActionResult GetGeneratedPassword()
    {
        var generator = new PasswordGenerator();
        return Json(new { password = generator.Generate(_options.PasswordEntropy) });
    }

    /// <summary>
    /// Given a POST request, processes and changes a User's password.
    /// </summary>
    /// <param name="model">The value.</param>
    /// <returns>A task representing the async operation.</returns>
    [HttpPost]
    public async Task<IActionResult> Post([FromBody] ChangePasswordModel model)
    {
        // Validate the model
        if (ModelState.IsValid == false)
        {
            _logger.LogWarning("Invalid model, validation failed");

            return BadRequest(ApiResult.FromModelStateErrors(ModelState));
        }

        // Validate the Captcha
        try
        {
            if (await ValidateRecaptcha(model.Recaptcha).ConfigureAwait(false) == false)
                throw new InvalidOperationException("Invalid Recaptcha response");
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Invalid Recaptcha");
            return BadRequest(ApiResult.InvalidCaptcha());
        }

        var result = new ApiResult();

        try
        {
            if (_options.MinimumDistance > 0 &&
                _passwordChangeProvider.MeasureNewPasswordDistance(model.CurrentPassword, model.NewPassword) < _options.MinimumDistance)
            {
                result.Errors.Add(new ApiErrorItem(ApiErrorCode.MinimumDistance));
                return BadRequest(result);
            }

            if (_options.MinimumScore > 0 && Core.EvaluatePassword(model.NewPassword).Score < _options.MinimumScore)
            {
                result.Errors.Add(new ApiErrorItem(ApiErrorCode.MinimumScore));
                return BadRequest(result);
            }

            var resultPasswordChange = await _passwordChangeProvider.PerformPasswordChangeAsync(
                model.Username,
                model.CurrentPassword,
                model.NewPassword);

            if (resultPasswordChange == null)
                return Json(result);

            result.Errors.Add(resultPasswordChange);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to update password");

            result.Errors.Add(new ApiErrorItem(ApiErrorCode.Generic, ex.Message));
        }

        return BadRequest(result);
    }

    private async Task<bool> ValidateRecaptcha(string? recaptchaResponse)
    {
        // skip validation if we don't enable recaptcha
        if (_options.Recaptcha != null && string.IsNullOrWhiteSpace(_options.Recaptcha.PrivateKey))
            return true;

        if (_options.Recaptcha == null || string.IsNullOrEmpty(recaptchaResponse))
            return false;

        var client = _httpClientFactory.CreateClient("Recaptcha");
        var response = await client.PostAsync("siteverify", new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string?, string?>("secret", _options.Recaptcha.PrivateKey),
            new KeyValuePair<string?, string?>("response", recaptchaResponse)
        }));

        response.EnsureSuccessStatusCode();

        var validationResponse = await JsonSerializer.DeserializeAsync<Dictionary<string, object>>(await response.Content.ReadAsStreamAsync());

        return validationResponse != null && validationResponse.TryGetValue("success", out var success) && ((JsonElement)success).GetBoolean();
    }
}