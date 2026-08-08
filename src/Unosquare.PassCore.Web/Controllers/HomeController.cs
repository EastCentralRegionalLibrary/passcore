using Microsoft.AspNetCore.Mvc;

namespace Unosquare.PassCore.Web.Controllers;

/// <summary>
/// This controller is simply a placeholder to redirect any non-matching URL
/// to provide the context of the SPA (single page application) index
/// Examine the routing configuration in the Startup class.
/// </summary>
public class HomeController : Controller
{
    /// <summary>
    /// Serves the single-page application's index HTML page.
    /// </summary>
    /// <returns>The index HTML file result.</returns>
    public IActionResult Index() => File("~/index.html", "text/html");
}