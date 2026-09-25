using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Data.Sqlite;
using Microsoft.IdentityModel.Tokens;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

var builder = WebApplication.CreateBuilder(args);

builder.Logging.ClearProviders();
builder.Logging.AddConsole();

builder.Services.AddControllers();

var jwtSettings = builder.Configuration.GetSection(JwtSettings.SectionName).Get<JwtSettings>()
    ?? throw new InvalidOperationException("JWT settings are missing.");

var adminSettings = builder.Configuration.GetSection(AdminSettings.SectionName).Get<AdminSettings>()
    ?? throw new InvalidOperationException("Admin settings are missing.");

if (string.IsNullOrWhiteSpace(adminSettings.Username) || string.IsNullOrWhiteSpace(adminSettings.Email) || string.IsNullOrWhiteSpace(adminSettings.Password))
    throw new InvalidOperationException("Admin username, email, and password must be configured.");

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
    });
builder.Services.AddAuthorization();

// create and open In-Memory-Database
var databaseConnection = new SqliteConnection("Data Source=:memory:");
databaseConnection.Open();

using (var command = databaseConnection.CreateCommand())
{
    command.CommandText =
        """
        CREATE TABLE IF NOT EXISTS Users (
            UserID INTEGER PRIMARY KEY AUTOINCREMENT,
            Username TEXT NOT NULL UNIQUE,
            Email TEXT NOT NULL UNIQUE,
            Password TEXT NOT NULL,
            Role TEXT NOT NULL
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
