using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault.Controllers;
using SafeVault.Data;

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

        var controller = new AuthenticationController(new UserRepository(connection));
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
                var result = controller.Login(request) as RedirectResult;

                Assert.That(result, Is.Not.Null);
                Assert.That(result!.Url, Is.EqualTo("/login.html"),
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

        var controller = new AuthenticationController(new UserRepository(connection));
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
}
