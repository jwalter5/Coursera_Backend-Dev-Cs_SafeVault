using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault.Controllers;
using SafeVault.Data;
using SafeVault.Models;

[TestFixture]
public class UsersControllerTests
{
    [Test]
    public void ChangePasswordChangesOnlyTheUserIdentifiedByTheToken()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var currentUser = CreateUser(repository, "current-user", "current@example.com");
        var otherUser = CreateUser(repository, "other-user", "other@example.com");
        var controller = CreateController(repository, currentUser.UserID.ToString());

        var result = controller.ChangePassword(new ChangePasswordRequest("password", "new-password"));

        Assert.That(result, Is.TypeOf<NoContentResult>());
        Assert.That(repository.GetByCredentials(currentUser.Username, "password"), Is.Null);
        Assert.That(repository.GetByCredentials(currentUser.Username, "new-password"), Is.Not.Null);
        Assert.That(repository.GetByCredentials(otherUser.Username, "password"), Is.Not.Null);
    }

    [Test]
    public void ChangePasswordRejectsAnIncorrectOldPassword()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var user = CreateUser(repository, "test-user", "test@example.com");
        var controller = CreateController(repository, user.UserID.ToString());

        var result = controller.ChangePassword(new ChangePasswordRequest("wrong-password", "new-password"));

        Assert.That(result, Is.TypeOf<BadRequestObjectResult>());
        Assert.That(repository.GetByCredentials(user.Username, "password"), Is.Not.Null);
        Assert.That(repository.GetByCredentials(user.Username, "new-password"), Is.Null);
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

    private static User CreateUser(UserRepository repository, string username, string email)
    {
        var user = new User
        {
            Username = username,
            Email = email,
            Password = "password",
            Role = "User"
        };
        user.UserID = repository.Create(user);
        return user;
    }

    private static UsersController CreateController(UserRepository repository, string subject)
    {
        var identity = new ClaimsIdentity(
            [new Claim(JwtRegisteredClaimNames.Sub, subject)],
            "TestAuthentication");

        return new UsersController(repository)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = new ClaimsPrincipal(identity)
                }
            }
        };
    }
}
