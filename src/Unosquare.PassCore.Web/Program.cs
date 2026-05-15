using System;
using System.Net.Http.Headers;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using PwnedPasswordsSearch;
using Unosquare.PassCore.Common;
using Unosquare.PassCore.Common.Models;
using Unosquare.PassCore.Common.Policies;
using Unosquare.PassCore.Web.Models;

#if PASSCORE_DEBUG_PROVIDER
using Unosquare.PassCore.PasswordProvider.Debug;
#elif PASSCORE_LDAP_PROVIDER
using Zyborg.PassCore.PasswordProvider.LDAP;
#elif PASSCORE_AD_PROVIDER
using Unosquare.PassCore.PasswordProvider;
#endif

var builder = WebApplication.CreateBuilder(args);

// -------------------------------------------------------------------------
// Bound configuration
// -------------------------------------------------------------------------
builder.Services.Configure<ClientSettings>(builder.Configuration.GetSection(nameof(ClientSettings)));
builder.Services.Configure<WebSettings>(builder.Configuration.GetSection(nameof(WebSettings)));

// -------------------------------------------------------------------------
// HTTP clients
// -------------------------------------------------------------------------
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

// -------------------------------------------------------------------------
// Password policies (evaluation order matches registration order)
// -------------------------------------------------------------------------
builder.Services.AddSingleton<IPasswordPolicy, LengthPasswordPolicy>();
builder.Services.AddSingleton<IPasswordPolicy, ComplexityPasswordPolicy>();
builder.Services.AddSingleton<IPasswordPolicy, DistancePasswordPolicy>();
builder.Services.AddSingleton<IPasswordPolicy, GroupMembershipPolicy>();
builder.Services.AddSingleton<IPasswordPolicy, PwnedPasswordPolicy>();

// -------------------------------------------------------------------------
// Password provider (selected at build time via PASSCORE_PROVIDER)
// -------------------------------------------------------------------------
#if PASSCORE_DEBUG_PROVIDER
if (builder.Environment.IsProduction())
    throw new InvalidOperationException("The debug password change provider cannot be used in Production.");

builder.Services.Configure<DebugProviderOptions>(builder.Configuration.GetSection(nameof(DebugProviderOptions)));
builder.Services.AddSingleton<IPasswordChangeProvider, DebugPasswordChangeProvider>();
#elif PASSCORE_LDAP_PROVIDER
builder.Services.Configure<LdapPasswordChangeOptions>(builder.Configuration.GetSection("AppSettings"));
builder.Services.AddSingleton<IPasswordChangeProvider, LdapPasswordChangeProvider>();
#elif PASSCORE_AD_PROVIDER
builder.Services.Configure<PasswordChangeOptions>(builder.Configuration.GetSection("AppSettings"));
builder.Services.AddSingleton<IPasswordChangeProvider, PasswordChangeProvider>();
#else
#error No PASSCORE_PROVIDER selected. Build with /p:PASSCORE_PROVIDER=DEBUG|LDAP|AD.
#endif

builder.Services.AddControllers();

var app = builder.Build();

var settings = app.Services.GetRequiredService<IOptions<WebSettings>>().Value;
if (settings.EnableHttpsRedirect)
    app.UseHttpsRedirection();

app.UseDefaultFiles();
app.UseStaticFiles();
app.UseRouting();
app.MapControllers();

app.Run();

public partial class Program;
