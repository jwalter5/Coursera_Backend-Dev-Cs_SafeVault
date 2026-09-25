using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using SafeVault.Controllers;
using SafeVault.Data;
using SafeVault.Services;

[TestFixture]
public class TestInputValidation
{
    [Test]
    public void TestForSQLInjection()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();

        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                """
                CREATE TABLE Users (
                    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                    Username TEXT NOT NULL,
                    Email TEXT NOT NULL,
                    Password TEXT NOT NULL,
                    Role TEXT NOT NULL
                );

                INSERT INTO Users (Username, Email, Password, Role)
                VALUES ('existingUser', 'existing@example.com', 'password', 'User');
                """;
            command.ExecuteNonQuery();
        }

        var controller = CreateController(new UserRepository(connection));
        var maliciousRequests = new[]
        {
            new LoginRequest
            {
                Username = "' OR 1=1 --",
                Password = "password"
            },
            new LoginRequest
            {
                Username = "attacker",
                Password = "' OR 1=1 --"
            }
        };

        Assert.Multiple(() =>
        {
            foreach (var request in maliciousRequests)
            {
                var result = controller.Login(request) as UnauthorizedObjectResult;

                Assert.That(result, Is.Not.Null);
                Assert.That(result!.StatusCode, Is.EqualTo(401),
                    $"SQL injection succeeded for username '{request.Username}' and password '{request.Password}'.");
            }
        });
    }

    [Test]
    public void TestForXSS()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();

        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                """
                CREATE TABLE Users (
                    UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                    Username TEXT NOT NULL,
                    Email TEXT NOT NULL,
                    Password TEXT NOT NULL,
                    Role TEXT NOT NULL
                );
                """;
            command.ExecuteNonQuery();
        }

        var controller = CreateController(new UserRepository(connection));
        const string xssPayload = "<script>alert('XSS')</script>";
        var maliciousRequests = new[]
        {
            new RegistrationRequest
            {
                Username = xssPayload,
                Email = "attacker@example.com",
                Password = "password"
            },
            new RegistrationRequest
            {
                Username = "attacker",
                Email = $"{xssPayload}@example.com",
                Password = "password"
            }
        };

        foreach (var request in maliciousRequests)
        {
            controller.CreateUser(request);
        }

        using var verificationCommand = connection.CreateCommand();
        verificationCommand.CommandText =
            """
            SELECT COUNT(*)
            FROM Users
            WHERE Username = $maliciousUsername
               OR Email = $maliciousEmail;
            """;
        verificationCommand.Parameters.AddWithValue("$maliciousUsername", xssPayload);
        verificationCommand.Parameters.AddWithValue("$maliciousEmail", $"{xssPayload}@example.com");

        var storedXssPayloads = Convert.ToInt32(verificationCommand.ExecuteScalar());

        Assert.That(storedXssPayloads, Is.Zero,
            "XSS payloads must be rejected or sanitized before they are stored.");
    }

    private static AuthenticationController CreateController(UserRepository repository)
    {
        var settings = Options.Create(new JwtSettings
        {
            Key = "a-test-signing-key-that-is-at-least-thirty-two-bytes-long",
            Issuer = "SafeVault.Tests",
            Audience = "SafeVault.Tests",
            ExpirationMinutes = 30
        });

        return new AuthenticationController(repository, new JwtTokenService(settings));
    }
}
