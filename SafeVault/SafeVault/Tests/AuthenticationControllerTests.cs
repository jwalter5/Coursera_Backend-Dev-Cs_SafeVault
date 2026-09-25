using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using SafeVault.Controllers;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

[TestFixture]
public class AuthenticationControllerTests
{
    [Test]
    public void CreateUserWithValidDataRegistersUserAndReturnsAuthenticationResponse()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var controller = CreateController(repository);
        var request = new RegistrationRequest
        {
            Username = "new-user",
            Email = "new.user@example.com",
            Password = "secure-password"
        };

        var result = controller.CreateUser(request);

        var okResult = result as OkObjectResult;
        var response = okResult?.Value as AuthenticationResponse;
        var registeredUser = repository.GetByCredentials(request.Username, request.Password);

        Assert.Multiple(() =>
        {
            Assert.That(okResult, Is.Not.Null);
            Assert.That(response, Is.Not.Null);
            Assert.That(response!.Token, Is.Not.Empty);
            Assert.That(response.User.Username, Is.EqualTo(request.Username));
            Assert.That(response.User.Email, Is.EqualTo(request.Email));
            Assert.That(response.User.Role, Is.EqualTo("User"));
            Assert.That(registeredUser, Is.Not.Null);
            Assert.That(response.User.UserId, Is.EqualTo(registeredUser!.UserID));
        });
    }

    [TestCase("invalid user", "user@example.com", "password")]
    [TestCase("<script>alert(1)</script>", "user@example.com", "password")]
    [TestCase("valid-user", "invalid email@example.com", "password")]
    [TestCase("valid-user", "user@example.com", " ")]
    public void CreateUserWithInvalidDataReturnsBadRequest(
        string username,
        string email,
        string password)
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var controller = CreateController(repository);
        var request = new RegistrationRequest
        {
            Username = username,
            Email = email,
            Password = password
        };

        var result = controller.CreateUser(request);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.TypeOf<BadRequestObjectResult>());
            Assert.That(repository.GetAll(), Is.Empty);
        });
    }

    [TestCase(true)]
    [TestCase(false)]
    public void CreateUserWithExistingUsernameOrEmailReturnsConflict(bool duplicateUsername)
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        CreateUser(repository, "existing-user", "existing@example.com", "password");
        var controller = CreateController(repository);
        var request = new RegistrationRequest
        {
            Username = duplicateUsername ? "existing-user" : "different-user",
            Email = duplicateUsername ? "different@example.com" : "existing@example.com",
            Password = "password"
        };

        var result = controller.CreateUser(request);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.TypeOf<ConflictObjectResult>());
            Assert.That(repository.GetAll(), Has.Count.EqualTo(1));
        });
    }

    [Test]
    public void LoginWithValidCredentialsReturnsAuthenticationResponse()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var user = CreateUser(repository, "existing-user", "existing@example.com", "password");
        var controller = CreateController(repository);

        var result = controller.Login(new LoginRequest
        {
            Username = user.Username,
            Password = "password"
        });

        var okResult = result as OkObjectResult;
        var response = okResult?.Value as AuthenticationResponse;

        Assert.Multiple(() =>
        {
            Assert.That(okResult, Is.Not.Null);
            Assert.That(response, Is.Not.Null);
            Assert.That(response!.Token, Is.Not.Empty);
            Assert.That(response.User.UserId, Is.EqualTo(user.UserID));
            Assert.That(response.User.Username, Is.EqualTo(user.Username));
            Assert.That(response.User.Role, Is.EqualTo(user.Role));
        });
    }

    [TestCase("existing-user", "wrong-password")]
    [TestCase("unknown-user", "password")]
    [TestCase("invalid user", "password")]
    [TestCase("existing-user", " ")]
    public void LoginWithInvalidDataReturnsUnauthorized(string username, string password)
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        CreateUser(repository, "existing-user", "existing@example.com", "password");
        var controller = CreateController(repository);

        var result = controller.Login(new LoginRequest
        {
            Username = username,
            Password = password
        });

        Assert.That(result, Is.TypeOf<UnauthorizedObjectResult>());
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
                Role TEXT NOT NULL
            );
            """;
        command.ExecuteNonQuery();

        return connection;
    }

    private static User CreateUser(
        UserRepository repository,
        string username,
        string email,
        string password)
    {
        var user = new User
        {
            Username = username,
            Email = email,
            Password = password,
            Role = "User"
        };
        user.UserID = repository.Create(user);
        return user;
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
