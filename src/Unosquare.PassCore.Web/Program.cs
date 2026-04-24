using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Unosquare.PassCore.Common.Models;
using Unosquare.PassCore.Web.Models;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Policies;
using PwnedPasswordsSearch;
using System.Net.Http.Headers;
using System;

#if DEBUG
using Unosquare.PassCore.PasswordProvider.Debug;
#elif PASSCORE_LDAP_PROVIDER
using Zyborg.PassCore.PasswordProvider.LDAP;
using Microsoft.Extensions.Logging;
#elif PASSCORE_AD_PROVIDER
using Unosquare.PassCore.PasswordProvider;
#endif

var builder = WebApplication.CreateBuilder(args);

// ConfigureServices
builder.Services.Configure<ClientSettings>(builder.Configuration.GetSection(nameof(ClientSettings)));
builder.Services.Configure<WebSettings>(builder.Configuration.GetSection(nameof(WebSettings)));

builder.Services.AddHttpClient("Recaptcha", client =>
{
    client.BaseAddress = new Uri("https://www.google.com/recaptcha/api/");
});

builder.Services.AddHttpClient("PwnedPasswords", client =>
{
    client.BaseAddress = new Uri("https://api.pwnedpasswords.com/");
    client.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("PassCore", "1.0"));
});

builder.Services.AddSingleton<IPwnedPasswordSearch, PwnedSearch>();

// Register Policies
builder.Services.AddSingleton<IPasswordPolicy, PwnedPasswordPolicy>();
builder.Services.AddSingleton<IPasswordPolicy, LengthPasswordPolicy>();
builder.Services.AddSingleton<IPasswordPolicy, ComplexityPasswordPolicy>();
builder.Services.AddSingleton<IPasswordPolicy, DistancePasswordPolicy>();
builder.Services.AddSingleton<IPasswordPolicy, GroupMembershipPolicy>();

#if DEBUG
if (builder.Environment.IsProduction())
{
    throw new InvalidOperationException("The debug password change provider cannot be used in Production.");
}

builder.Services.Configure<IAppSettings>(builder.Configuration.GetSection("AppSettings"));
builder.Services.Configure<DebugProviderOptions>(builder.Configuration.GetSection(nameof(DebugProviderOptions)));
builder.Services.AddSingleton<IPasswordChangeProvider, DebugPasswordChangeProvider>();
#elif PASSCORE_LDAP_PROVIDER
builder.Services.Configure<LdapPasswordChangeOptions>(builder.Configuration.GetSection("AppSettings"));
builder.Services.AddSingleton<IPasswordChangeProvider, LdapPasswordChangeProvider>();
builder.Services.AddSingleton<ILoggerFactory, LoggerFactory>();
builder.Services.AddSingleton(typeof(ILogger), sp =>
{
    var loggerFactory = sp.GetService<ILoggerFactory>();
    return loggerFactory.CreateLogger("PassCoreLDAPProvider");
});
#else
builder.Services.Configure<PasswordChangeOptions>(builder.Configuration.GetSection("AppSettings"));
builder.Services.AddSingleton<IPasswordChangeProvider, PasswordChangeProvider>();
#endif

builder.Services.AddControllers();

var app = builder.Build();

// Configure
var settings = app.Services.GetRequiredService<IOptions<WebSettings>>().Value;

if (settings.EnableHttpsRedirect)
    app.UseHttpsRedirection();

app.UseDefaultFiles();
app.UseStaticFiles();

app.UseRouting();

app.MapControllers();

app.Run();
