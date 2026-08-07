using System.Net.Http;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Unosquare.PassCore.Common.Models;
using Unosquare.PassCore.Web.Helpers;
using Unosquare.PassCore.Web.Models;

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

    private static readonly Action<ILogger, Exception?> LogInvalidModel =
        LoggerMessage.Define(
            LogLevel.Warning,
            new EventId(200, "InvalidModel"),
            "Invalid model, validation failed");

    private static readonly Action<ILogger, Exception?> LogInvalidRecaptcha =
        LoggerMessage.Define(
            LogLevel.Warning,
            new EventId(201, "InvalidRecaptcha"),
            "Invalid Recaptcha");

    private static readonly Action<ILogger, string, Exception?> LogFailedToUpdatePassword =
        LoggerMessage.Define<string>(
            LogLevel.Error,
            new EventId(202, "FailedToUpdatePassword"),
            "Failed to update password (ref: {Reference})");

    /// <summary>
    /// Initializes a new instance of the <see cref="PasswordController" /> class.
    /// </summary>
    /// <param name="logger">The logger.</param>
    /// <param name="optionsAccessor">The options accessor.</param>
    /// <param name="passwordChangeProvider">The password change provider.</param>
    /// <param name="httpClientFactory">The HTTP client factory.</param>
    public PasswordController(
        ILogger<PasswordController> logger,
        IOptions<ClientSettings> optionsAccessor,
        IPasswordChangeProvider passwordChangeProvider,
        IHttpClientFactory httpClientFactory)
    {
        ArgumentNullException.ThrowIfNull(optionsAccessor);
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
        return Json(new { password = PasswordGenerator.Generate(_options.PasswordEntropy) });
    }

    /// <summary>
    /// Given a POST request, processes and changes a User's password.
    /// </summary>
    /// <param name="model">The value.</param>
    /// <returns>A task representing the async operation.</returns>
    [HttpPost]
    public async Task<IActionResult> Post([FromBody] ChangePasswordModel model)
    {
        ArgumentNullException.ThrowIfNull(model);

        // Validate the model
        if (!ModelState.IsValid)
        {
            LogInvalidModel(_logger, null);

            return BadRequest(ApiResult.FromModelStateErrors(ModelState));
        }

        // Validate the Captcha
        try
        {
            if (!await ValidateRecaptcha(model.Recaptcha).ConfigureAwait(false))
                throw new InvalidOperationException("Invalid Recaptcha response");
        }
        catch (InvalidOperationException ex)
        {
            LogInvalidRecaptcha(_logger, ex);
            return BadRequest(ApiResult.InvalidCaptcha());
        }

        var result = new ApiResult();

        try
        {
            var resultPasswordChange = await _passwordChangeProvider.PerformPasswordChangeAsync(model.Username, model.CurrentPassword, model.NewPassword);

            if (resultPasswordChange.IsSuccessful)
                return Json(result);

            foreach (var error in resultPasswordChange.Errors)
                result.Errors.Add(error);
        }
        catch (HttpRequestException ex)
        {
            result.Errors.Add(UnexpectedError(ex));
        }
        catch (InvalidOperationException ex)
        {
            result.Errors.Add(UnexpectedError(ex));
        }

        return BadRequest(result);
    }

    /// <summary>
    /// Logs the exception under a fresh correlation reference and returns a
    /// clean Generic error carrying only that reference — the Generic code's
    /// message renders verbatim in the UI, so raw exception text must never
    /// be placed in it.
    /// </summary>
    private ApiErrorItem UnexpectedError(Exception ex)
    {
        var reference = Guid.NewGuid().ToString("N")[..8];
        LogFailedToUpdatePassword(_logger, reference, ex);

        return new ApiErrorItem(ApiErrorCode.Generic, $"An unexpected error occurred (ref: {reference})");
    }

    private async Task<bool> ValidateRecaptcha(string? recaptchaResponse)
    {
        // skip validation if we don't enable recaptcha
        if (_options.Recaptcha != null && string.IsNullOrWhiteSpace(_options.Recaptcha.PrivateKey))
            return true;

        if (_options.Recaptcha == null || string.IsNullOrEmpty(recaptchaResponse))
            return false;

        var client = _httpClientFactory.CreateClient("Recaptcha");
        using var content = new FormUrlEncodedContent(new[]
        {
            new KeyValuePair<string?, string?>("secret", _options.Recaptcha.PrivateKey),
            new KeyValuePair<string?, string?>("response", recaptchaResponse)
        });
        using var response = await client.PostAsync(new Uri("siteverify", UriKind.Relative), content);

        try
        {
            response.EnsureSuccessStatusCode();
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException("Recaptcha API request failed.", ex);
        }

        var validationResponse = await JsonSerializer.DeserializeAsync<Dictionary<string, object>>(await response.Content.ReadAsStreamAsync());

        return validationResponse != null && validationResponse.TryGetValue("success", out var success) && ((JsonElement)success).GetBoolean();
    }
}
