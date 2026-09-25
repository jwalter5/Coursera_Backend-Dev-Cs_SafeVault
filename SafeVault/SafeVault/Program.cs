using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using SafeVault.Utilities;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();

builder.Services.AddControllersWithViews(options =>
    options.Filters.Add(new AutoValidateAntiforgeryTokenAttribute()));
builder.Services.AddAntiforgery(options =>
{
    options.HeaderName = "X-CSRF-TOKEN";
    options.Cookie.Name = "__Host-SafeVaultCsrf";
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Strict;
    options.Cookie.Path = "/";
});

var jwtSettings = builder.Configuration.GetSection(JwtSettings.SectionName).Get<JwtSettings>()
    ?? throw new InvalidOperationException("JWT settings are missing.");

var adminSettings = builder.Configuration.GetSection(AdminSettings.SectionName).Get<AdminSettings>()
    ?? throw new InvalidOperationException("Admin settings are missing.");

if (!UserCreationValidator.IsValid(
        adminSettings.Username,
        adminSettings.Email,
        adminSettings.Password))
    throw new InvalidOperationException("Admin username, email, or password is invalid.");

if (Encoding.UTF8.GetByteCount(jwtSettings.Key) < 32)
    throw new InvalidOperationException("The JWT signing key must be at least 32 bytes long.");

builder.Services.Configure<JwtSettings>(builder.Configuration.GetSection(JwtSettings.SectionName));
builder.Services.AddSingleton<JwtTokenService>();
builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.MapInboundClaims = false;
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings.Issuer,
            ValidAudience = jwtSettings.Audience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Key)),
            NameClaimType = "name",
            RoleClaimType = "role",
            ClockSkew = TimeSpan.Zero
        };
        options.Events = new JwtBearerEvents
        {
            OnMessageReceived = context =>
            {
                context.Token = context.Request.Cookies[AuthenticationCookie.Name];
                return Task.CompletedTask;
            }
        };
    });
builder.Services.AddAuthorization();

// create and open In-Memory-Database
var databaseConnection = new SqliteConnection("Data Source=:memory:");
databaseConnection.Open();

using (var command = databaseConnection.CreateCommand())
{
    command.CommandText =
        $"""
        CREATE TABLE IF NOT EXISTS Users (
            UserID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL UNIQUE
                CHECK (length(Username) BETWEEN 1 AND {UserInputLimits.UsernameMaxLength}),
            Email TEXT NOT NULL UNIQUE
                CHECK (length(Email) BETWEEN 1 AND {UserInputLimits.EmailMaxLength}),
            Password TEXT NOT NULL
                CHECK (length(Password) BETWEEN 1 AND {UserInputLimits.PasswordHashMaxLength}),
            Role TEXT NOT NULL
                CHECK (length(Role) BETWEEN 1 AND {UserInputLimits.RoleMaxLength})
        );
        """;

    command.ExecuteNonQuery();
}

var userRepository = new UserRepository(databaseConnection);
userRepository.Create(new User
{
    Username = adminSettings.Username,
    Email = adminSettings.Email,
    Password = adminSettings.Password,
    Role = "Admin"
});

builder.Services.AddSingleton(databaseConnection);
builder.Services.AddSingleton(userRepository);

var app = builder.Build();

if (!app.Environment.IsDevelopment())
    app.UseHsts();

app.UseHttpsRedirection();

var defaultFileOptions = new DefaultFilesOptions();
defaultFileOptions.DefaultFileNames.Clear();
defaultFileOptions.DefaultFileNames.Add("index.html");

app.UseDefaultFiles(defaultFileOptions);
app.UseStaticFiles();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Cleanly close database connection
app.Lifetime.ApplicationStopping.Register(databaseConnection.Dispose);

app.Run();
