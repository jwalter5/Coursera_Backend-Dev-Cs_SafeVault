using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using SafeVault.Controllers;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

[TestFixture]
public class PersonalDataTests
{
    private const string EncryptionKey = "U2FmZVZhdWx0LXRlc3QtQUVTLWtleS0zMi1ieXRlcyE=";

    [Test]
    public void PersonalDataIsStoredEncryptedAndCanBeReadByItsOwner()
    {
        using var connection = CreateDatabase();
        var repository = CreateRepository(connection);
        var user = CreateUser(repository, "owner", "owner@example.com");
        var message = new string('x', 255) + " private message";

        var saved = repository.SavePersonalData(user.UserID, message);
        var storedValue = ReadStoredPersonalData(connection, user.UserID);

        Assert.Multiple(() =>
        {
            Assert.That(saved, Is.True);
            Assert.That(storedValue, Is.Not.EqualTo(message));
            Assert.That(storedValue, Does.Not.Contain(message));
            Assert.That(repository.GetPersonalData(user.UserID), Is.EqualTo(message));
        });
    }

    [Test]
    public void CiphertextCannotBeMovedToAnotherUser()
    {
        using var connection = CreateDatabase();
        var repository = CreateRepository(connection);
        var firstUser = CreateUser(repository, "first", "first@example.com");
        var secondUser = CreateUser(repository, "second", "second@example.com");
        repository.SavePersonalData(firstUser.UserID, "first user's secret");

        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                "UPDATE Users SET PersonalData = (SELECT PersonalData FROM Users WHERE UserID = $firstId) WHERE UserID = $secondId;";
            command.Parameters.AddWithValue("$firstId", firstUser.UserID);
            command.Parameters.AddWithValue("$secondId", secondUser.UserID);
            command.ExecuteNonQuery();
        }

        Assert.Throws<System.Security.Cryptography.AuthenticationTagMismatchException>(
            () => repository.GetPersonalData(secondUser.UserID));
    }

    [Test]
    public void AdminEndpointReadsOnlyTheAuthenticatedAdminsOwnData()
    {
        using var connection = CreateDatabase();
        var repository = CreateRepository(connection);
        var admin = CreateUser(repository, "admin", "admin@example.com", "Admin");
        var otherUser = CreateUser(repository, "other", "other@example.com");
        repository.SavePersonalData(admin.UserID, "admin secret");
        repository.SavePersonalData(otherUser.UserID, "other secret");
        var controller = CreateController(repository, admin);
        controller.Request.Headers["id"] = otherUser.UserID.ToString();

        var result = controller.ViewPersonalData(new ViewPersonalDataRequest("password"));

        var response = (result.Result as OkObjectResult)?.Value as PersonalDataResponse;
        Assert.That(response?.PersonalData, Is.EqualTo("admin secret"));
    }

    [Test]
    public void ViewEndpointRejectsAnIncorrectPassword()
    {
        using var connection = CreateDatabase();
        var repository = CreateRepository(connection);
        var user = CreateUser(repository, "owner", "owner@example.com");
        repository.SavePersonalData(user.UserID, "owner secret");
        var controller = CreateController(repository, user);

        var result = controller.ViewPersonalData(new ViewPersonalDataRequest("wrong-password"));

        Assert.That(result.Result, Is.TypeOf<BadRequestObjectResult>());
    }

    [Test]
    public void SaveEndpointRejectsDataBeyondConfiguredLimit()
    {
        using var connection = CreateDatabase();
        var repository = CreateRepository(connection);
        var user = CreateUser(repository, "owner", "owner@example.com");
        var controller = CreateController(repository, user);

        var result = controller.SavePersonalData(
            new SavePersonalDataRequest(new string('x', UserInputLimits.PersonalDataMaxLength + 1)));

        Assert.That(result, Is.TypeOf<BadRequestObjectResult>());
        Assert.That(repository.GetPersonalData(user.UserID), Is.Null);
    }

    private static UserRepository CreateRepository(SqliteConnection connection)
    {
        var encryption = new PersonalDataEncryptionService(Options.Create(new AesSettings
        {
            Key = EncryptionKey
        }));
        return new UserRepository(connection, encryption);
    }

    private static SqliteConnection CreateDatabase()
    {
        var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        using var command = connection.CreateCommand();
        command.CommandText =
            """
            CREATE TABLE Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL,
                Email TEXT NOT NULL,
                Password TEXT NOT NULL,
                Role TEXT NOT NULL,
                PersonalData VARCHAR
            );
            """;
        command.ExecuteNonQuery();
        return connection;
    }

    private static User CreateUser(
        UserRepository repository,
        string username,
        string email,
        string role = "User")
    {
        var user = new User
        {
            Username = username,
            Email = email,
            Password = "password",
            Role = role
        };
        user.UserID = repository.Create(user);
        return user;
    }

    private static UsersController CreateController(UserRepository repository, User user)
    {
        var jwtSettings = Options.Create(new JwtSettings
        {
            Key = "a-test-signing-key-that-is-at-least-thirty-two-bytes-long",
            Issuer = "SafeVault.Tests",
            Audience = "SafeVault.Tests",
            ExpirationMinutes = 30
        });
        var principal = new ClaimsPrincipal(new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, user.UserID.ToString()),
                new Claim(ClaimTypes.Role, user.Role)
            ],
            "TestAuthentication"));

        return new UsersController(repository, new JwtTokenService(jwtSettings))
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext { User = principal }
            }
        };
    }

    private static string ReadStoredPersonalData(SqliteConnection connection, int userId)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT PersonalData FROM Users WHERE UserID = $userId;";
        command.Parameters.AddWithValue("$userId", userId);
        return (string)command.ExecuteScalar()!;
    }
}
