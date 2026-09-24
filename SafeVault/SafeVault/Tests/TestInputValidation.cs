using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault.Controllers;

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
                    Email TEXT NOT NULL
                );

                INSERT INTO Users (Username, Email)
                VALUES ('existingUser', 'existing@example.com');
                """;
            command.ExecuteNonQuery();
        }

        var controller = new AuthenticationController(connection);
        var maliciousRequests = new[]
        {
            new SubmitRequest
            {
                Username = "' OR 1=1 --",
                Email = "attacker@example.com"
            },
            new SubmitRequest
            {
                Username = "attacker",
                Email = "' OR 1=1 --"
            }
        };

        Assert.Multiple(() =>
        {
            foreach (var request in maliciousRequests)
            {
                var result = controller.Login(request) as OkObjectResult;

                Assert.That(result, Is.Not.Null);
                Assert.That(result!.Value, Is.EqualTo(false),
                    $"SQL injection succeeded for username '{request.Username}' and email '{request.Email}'.");
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
                    Email TEXT NOT NULL
                );
                """;
            command.ExecuteNonQuery();
        }

        var controller = new AuthenticationController(connection);
        const string xssPayload = "<script>alert('XSS')</script>";
        var maliciousRequests = new[]
        {
            new SubmitRequest
            {
                Username = xssPayload,
                Email = "attacker@example.com"
            },
            new SubmitRequest
            {
                Username = "attacker",
                Email = $"{xssPayload}@example.com"
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
