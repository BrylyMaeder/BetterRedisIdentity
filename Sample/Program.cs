using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Sample.Components;
using Sample.Components.Account;
using Sample.Data;
using BetterRedisIdentity;
using BetterRedisIdentity.Util;
using AsyncRedisDocuments;
using BetterRedisIdentity.Stores;
using AsyncRedisDocuments.Index;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

RedisSingleton.Initialize("redis-13464.c81.us-east-1-2.ec2.redns.redis-cloud.com", 13464, "4TdQe8UepIdXwrGBGSJwTl5s1nsvYpgN");

builder.Services.AddRedisIdentityStores<ApplicationUser, ApplicationRole>();

builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(options =>
{
    options.SignIn.RequireConfirmedAccount = false;
    options.User.RequireUniqueEmail = true;

}).AddDefaultTokenProviders() 
    .AddSignInManager(); 

// Authentication setup
builder.Services.AddAuthentication(options =>
{
    options.DefaultScheme = IdentityConstants.BearerScheme;
    options.DefaultSignInScheme = IdentityConstants.BearerScheme;
}).AddBearerToken();

// Add custom email sender for Identity
builder.Services.AddSingleton<IEmailSender<ApplicationUser>, IdentityNoOpEmailSender>();

// Add scoped services for Identity support in Razor Components
builder.Services.AddCascadingAuthenticationState();
builder.Services.AddScoped<IdentityUserAccessor>();
builder.Services.AddScoped<IdentityRedirectManager>();
builder.Services.AddScoped<AuthenticationStateProvider, IdentityRevalidatingAuthenticationStateProvider>();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
    app.UseMigrationsEndPoint();
}
else
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();

// Antiforgery for security
app.UseAntiforgery();

// Static assets and Razor Components
app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

// Add Identity-related endpoints (e.g., login, logout)
app.MapAdditionalIdentityEndpoints();

app.Run();
