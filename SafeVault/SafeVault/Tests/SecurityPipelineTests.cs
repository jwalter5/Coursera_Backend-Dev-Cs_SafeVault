using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using NUnit.Framework;
using SafeVault.Controllers;
using SafeVault.Services;

[TestFixture]
public sealed class SecurityPipelineTests
{
    private const string AdminUsername = "integration-admin";
    private const string AdminPassword = "integration-admin-password";
    private const string SigningKey = "integration-test-signing-key-that-is-at-least-32-bytes";
    private const string Issuer = "SafeVault.IntegrationTests";
    private const string Audience = "SafeVault.IntegrationTests.Web";

    [TestCase(InvalidTokenKind.Expired)]
    [TestCase(InvalidTokenKind.Malformed)]
    [TestCase(InvalidTokenKind.WrongIssuer)]
    [TestCase(InvalidTokenKind.WrongAudience)]
    [TestCase(InvalidTokenKind.WrongSignature)]
    public async Task ProtectedEndpointRejectsInvalidJwt(InvalidTokenKind tokenKind)
    {
        await using var factory = new SafeVaultWebApplicationFactory();
        using var client = factory.CreateHttpsClient(handleCookies: false);
        using var request = new HttpRequestMessage(HttpMethod.Get, "/api/users");
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            CreateInvalidToken(tokenKind, factory.JwtSettings));

        using var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task ProtectedEndpointRejectsMissingJwt()
    {
        await using var factory = new SafeVaultWebApplicationFactory();
        using var client = factory.CreateHttpsClient();

        using var response = await client.GetAsync("/api/users");

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    [Test]
    public async Task AuthenticationFailureReturns401ButInsufficientRoleReturns403()
    {
        await using var factory = new SafeVaultWebApplicationFactory();
        using var anonymousClient = factory.CreateHttpsClient();
        using var userClient = factory.CreateHttpsClient();

        using var unauthenticatedResponse = await anonymousClient.GetAsync("/api/users/all");
        await Register(userClient, "regular-user", "regular@example.com", "regular-password");
        using var forbiddenResponse = await userClient.GetAsync("/api/users/all");

        Assert.Multiple(() =>
        {
            Assert.That(unauthenticatedResponse.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
            Assert.That(forbiddenResponse.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        });
    }

    [Test]
    public async Task NonAdminCannotAccessAnyAdministratorEndpoint()
    {
        await using var factory = new SafeVaultWebApplicationFactory();
        using var client = factory.CreateHttpsClient();
        var userId = await Register(client, "regular-user", "regular@example.com", "regular-password");

        using var getAllResponse = await client.GetAsync("/api/users/all");
        using var updateRoleResponse = await SendJsonWithAntiforgery(
            client,
            HttpMethod.Put,
            "/api/users/role",
            new UpdateUserRoleRequest(userId, "Admin", "regular-password"));

        Assert.Multiple(() =>
        {
            Assert.That(getAllResponse.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(updateRoleResponse.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        });
    }

    [Test]
    public async Task UserCannotReadOrDeleteAnotherAccount()
    {
        await using var factory = new SafeVaultWebApplicationFactory();
        using var firstClient = factory.CreateHttpsClient();
        using var secondClient = factory.CreateHttpsClient();
        await Register(firstClient, "first-user", "first@example.com", "first-password");
        var secondUserId = await Register(secondClient, "second-user", "second@example.com", "second-password");

        using var getRequest = new HttpRequestMessage(HttpMethod.Get, "/api/users");
        getRequest.Headers.Add("id", secondUserId.ToString());
        using var getResponse = await firstClient.SendAsync(getRequest);

        using var deleteResponse = await SendJsonWithAntiforgery(
            firstClient,
            HttpMethod.Delete,
            "/api/users",
            new DeleteUserRequest("first-password"),
            request => request.Headers.Add("id", secondUserId.ToString()));

        Assert.Multiple(() =>
        {
            Assert.That(getResponse.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
            Assert.That(deleteResponse.StatusCode, Is.EqualTo(HttpStatusCode.Forbidden));
        });
    }

    [Test]
    public async Task UnsafeEndpointRejectsMissingAntiforgeryToken()
    {
        await using var factory = new SafeVaultWebApplicationFactory();
        using var client = factory.CreateHttpsClient();

        using var response = await client.PostAsJsonAsync("/api/auth/login", new LoginRequest
        {
            Username = AdminUsername,
            Password = AdminPassword
        });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task UnsafeEndpointRejectsInvalidAntiforgeryToken()
    {
        await using var factory = new SafeVaultWebApplicationFactory();
        using var client = factory.CreateHttpsClient();
        await GetAntiforgeryToken(client);
        using var request = new HttpRequestMessage(HttpMethod.Post, "/api/auth/login")
        {
            Content = JsonContent.Create(new LoginRequest
            {
                Username = AdminUsername,
                Password = AdminPassword
            })
        };
        request.Headers.Add("X-CSRF-TOKEN", "invalid-antiforgery-token");

        using var response = await client.SendAsync(request);

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.BadRequest));
    }

    [Test]
    public async Task DeletedUsersOldJwtStillAuthenticatesButResourceNoLongerExists()
    {
        await using var factory = new SafeVaultWebApplicationFactory();
        using var userClient = factory.CreateHttpsClient();
        var registration = await RegisterWithResponse(
            userClient,
            "deleted-user",
            "deleted@example.com",
            "deleted-password");
        var oldToken = ReadAuthenticationToken(registration.Response);
        registration.Response.Dispose();

        using var deleteResponse = await SendJsonWithAntiforgery(
            userClient,
            HttpMethod.Delete,
            "/api/users",
            new DeleteUserRequest("deleted-password"));
        using var replayResponse = await SendWithToken(HttpMethod.Get, "/api/users", oldToken, factory);

        Assert.Multiple(() =>
        {
            Assert.That(deleteResponse.StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
            Assert.That(replayResponse.StatusCode, Is.EqualTo(HttpStatusCode.NotFound));
        });
    }

    [Test]
    public async Task DemotedAdministratorsOldJwtRetainsItsRoleUntilExpiration()
    {
        await using var factory = new SafeVaultWebApplicationFactory();
        using var adminClient = factory.CreateHttpsClient();
        using var backupAdminClient = factory.CreateHttpsClient();
        var adminId = await Register(
            adminClient,
            "acting-admin",
            "acting-admin@example.com",
            "acting-admin-password");
        var backupAdminId = await Register(
            backupAdminClient,
            "backup-admin",
            "backup@example.com",
            "backup-password");
        var repository = factory.Services.GetRequiredService<SafeVault.Data.UserRepository>();
        Assert.That(
            repository.UpdateRole(adminId, "Admin"),
            Is.EqualTo(SafeVault.Data.UserMutationResult.Success));
        Assert.That(
            repository.UpdateRole(backupAdminId, "Admin"),
            Is.EqualTo(SafeVault.Data.UserMutationResult.Success));
        var adminLogin = await Login(adminClient, "acting-admin", "acting-admin-password");
        var oldAdminToken = adminLogin.Token;
        using var demoteResponse = await SendJsonWithAntiforgery(
            adminClient,
            HttpMethod.Put,
            "/api/users/role",
            new UpdateUserRoleRequest(adminId, "User", "acting-admin-password"));
        using var replayResponse = await SendWithToken(HttpMethod.Get, "/api/users/all", oldAdminToken, factory);

        Assert.Multiple(() =>
        {
            Assert.That(demoteResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
            Assert.That(replayResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });
    }

    [Test]
    public async Task PasswordChangeIssuesCookieButOldJwtRemainsValidUntilExpiration()
    {
        await using var factory = new SafeVaultWebApplicationFactory();
        using var userClient = factory.CreateHttpsClient();
        var registration = await RegisterWithResponse(
            userClient,
            "password-user",
            "password@example.com",
            "old-password");
        var oldToken = ReadAuthenticationToken(registration.Response);
        registration.Response.Dispose();

        using var changeResponse = await SendJsonWithAntiforgery(
            userClient,
            HttpMethod.Put,
            "/api/users/changePassword",
            new ChangePasswordRequest("old-password", "new-password"));
        var issuedToken = ReadAuthenticationToken(changeResponse);
        using var replayResponse = await SendWithToken(HttpMethod.Get, "/api/users", oldToken, factory);

        Assert.Multiple(() =>
        {
            Assert.That(changeResponse.StatusCode, Is.EqualTo(HttpStatusCode.NoContent));
            Assert.That(issuedToken, Is.Not.Empty);
            Assert.That(replayResponse.StatusCode, Is.EqualTo(HttpStatusCode.OK));
        });
    }

    [Test]
    [Explicit("Pending security control: no login rate limiter has been implemented yet.")]
    public async Task RepeatedFailedLoginsAreRateLimited()
    {
        await using var factory = new SafeVaultWebApplicationFactory();
        using var client = factory.CreateHttpsClient();
        await Register(client, "rate-limit-user", "rate-limit@example.com", "correct-password");
        var statuses = new List<HttpStatusCode>();

        for (var attempt = 0; attempt < 20; attempt++)
        {
            using var response = await SendJsonWithAntiforgery(
                client,
                HttpMethod.Post,
                "/api/auth/login",
                new LoginRequest { Username = "rate-limit-user", Password = "wrong-password" });
            statuses.Add(response.StatusCode);
        }

        Assert.That(statuses, Does.Contain(HttpStatusCode.TooManyRequests));
    }

    [Test]
    [Explicit("Pending security control: account lockout state has not been implemented yet.")]
    public async Task AccountLocksAfterRepeatedFailedLogins()
    {
        await using var factory = new SafeVaultWebApplicationFactory();
        using var client = factory.CreateHttpsClient();
        await Register(client, "lockout-user", "lockout@example.com", "correct-password");

        for (var attempt = 0; attempt < 10; attempt++)
        {
            using var failedResponse = await SendJsonWithAntiforgery(
                client,
                HttpMethod.Post,
                "/api/auth/login",
                new LoginRequest { Username = "lockout-user", Password = "wrong-password" });
        }

        using var response = await SendJsonWithAntiforgery(
            client,
            HttpMethod.Post,
            "/api/auth/login",
            new LoginRequest { Username = "lockout-user", Password = "correct-password" });

        Assert.That(response.StatusCode, Is.EqualTo(HttpStatusCode.Unauthorized));
    }

    private static async Task<int> Register(
        HttpClient client,
        string username,
        string email,
        string password)
    {
        var registration = await RegisterWithResponse(client, username, email, password);
        using var response = registration.Response;
        return registration.UserId;
    }

    private static async Task<(HttpResponseMessage Response, int UserId)> RegisterWithResponse(
        HttpClient client,
        string username,
        string email,
        string password)
    {
        var response = await SendJsonWithAntiforgery(
            client,
            HttpMethod.Post,
            "/api/auth/register",
            new RegistrationRequest
            {
                Username = username,
                Email = email,
                Password = password
            });
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<JsonElement>();
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(
            "Bearer",
            ReadAuthenticationToken(response));
        return (response, payload.GetProperty("user").GetProperty("userId").GetInt32());
    }

    private static async Task<(int UserId, string Token)> Login(
        HttpClient client,
        string username,
        string password)
    {
        using var response = await SendJsonWithAntiforgery(
            client,
            HttpMethod.Post,
            "/api/auth/login",
            new LoginRequest { Username = username, Password = password });
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<JsonElement>();
        var token = ReadAuthenticationToken(response);
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return (payload.GetProperty("user").GetProperty("userId").GetInt32(), token);
    }

    private static async Task<HttpResponseMessage> SendJsonWithAntiforgery<T>(
        HttpClient client,
        HttpMethod method,
        string path,
        T body,
        Action<HttpRequestMessage>? configure = null)
    {
        var token = await GetAntiforgeryToken(client);
        var request = new HttpRequestMessage(method, path)
        {
            Content = JsonContent.Create(body)
        };
        request.Headers.Add("X-CSRF-TOKEN", token);
        configure?.Invoke(request);
        return await client.SendAsync(request);
    }

    private static async Task<string> GetAntiforgeryToken(HttpClient client)
    {
        using var response = await client.GetAsync("/api/auth/antiforgery-token");
        response.EnsureSuccessStatusCode();
        var payload = await response.Content.ReadFromJsonAsync<JsonElement>();
        return payload.GetProperty("token").GetString()!;
    }

    private static async Task<HttpResponseMessage> SendWithToken(
        HttpMethod method,
        string path,
        string token,
        SafeVaultWebApplicationFactory factory)
    {
        using var client = factory.CreateHttpsClient(handleCookies: false);
        using var request = new HttpRequestMessage(method, path);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return await client.SendAsync(request);
    }

    private static string ReadAuthenticationToken(HttpResponseMessage response)
    {
        var prefix = $"{AuthenticationCookie.Name}=";
        var setCookie = response.Headers.GetValues("Set-Cookie")
            .Single(value => value.StartsWith(prefix, StringComparison.Ordinal));
        return setCookie[prefix.Length..setCookie.IndexOf(';')];
    }

    private static string CreateInvalidToken(InvalidTokenKind tokenKind, JwtSettings settings)
    {
        if (tokenKind == InvalidTokenKind.Malformed)
            return "not-a-jwt";

        var now = DateTime.UtcNow;
        var issuer = tokenKind == InvalidTokenKind.WrongIssuer ? "WrongIssuer" : settings.Issuer;
        var audience = tokenKind == InvalidTokenKind.WrongAudience ? "WrongAudience" : settings.Audience;
        var key = tokenKind == InvalidTokenKind.WrongSignature
            ? "different-integration-test-signing-key-at-least-32-bytes"
            : settings.Key;
        var expires = tokenKind == InvalidTokenKind.Expired ? now.AddMinutes(-1) : now.AddMinutes(30);
        var notBefore = tokenKind == InvalidTokenKind.Expired ? now.AddMinutes(-31) : now.AddMinutes(-1);
        var token = new JwtSecurityToken(
            issuer,
            audience,
            [
                new Claim(JwtRegisteredClaimNames.Sub, "1"),
                new Claim("name", "test-user"),
                new Claim("role", "User")
            ],
            notBefore,
            expires,
            new SigningCredentials(
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                SecurityAlgorithms.HmacSha256));
        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    public enum InvalidTokenKind
    {
        Expired,
        Malformed,
        WrongIssuer,
        WrongAudience,
        WrongSignature
    }

    private sealed class SafeVaultWebApplicationFactory : WebApplicationFactory<Program>
    {
        public JwtSettings JwtSettings => Services.GetRequiredService<IOptions<JwtSettings>>().Value;

        protected override void ConfigureWebHost(IWebHostBuilder builder)
        {
            builder.UseEnvironment("Development");
            builder.ConfigureAppConfiguration((_, configuration) =>
                configuration.AddInMemoryCollection(new Dictionary<string, string?>
                {
                    ["Jwt:Key"] = SigningKey,
                    ["Jwt:Issuer"] = Issuer,
                    ["Jwt:Audience"] = Audience,
                    ["Jwt:ExpirationMinutes"] = "30",
                    ["Admin:Username"] = AdminUsername,
                    ["Admin:Email"] = "integration-admin@example.com",
                    ["Admin:Password"] = AdminPassword
                }));
            builder.ConfigureServices(services =>
                services.PostConfigure<JwtBearerOptions>(
                    JwtBearerDefaults.AuthenticationScheme,
                    options =>
                    {
                        options.TokenValidationParameters.ValidIssuer = Issuer;
                        options.TokenValidationParameters.ValidAudience = Audience;
                        options.TokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(
                            Encoding.UTF8.GetBytes(SigningKey));
                    }));
        }

        public HttpClient CreateHttpsClient(bool handleCookies = true) =>
            CreateClient(new WebApplicationFactoryClientOptions
            {
                BaseAddress = new Uri("https://localhost"),
                AllowAutoRedirect = false,
                HandleCookies = handleCookies
            });
    }
}
