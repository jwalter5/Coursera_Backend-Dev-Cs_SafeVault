using System.IdentityModel.Tokens.Jwt;
using System.Reflection;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using SafeVault.Controllers;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

[TestFixture]
public class UsersControllerTests
{
    [TestCase(nameof(UsersController.GetAll))]
    [TestCase(nameof(UsersController.GetById))]
    [TestCase(nameof(UsersController.Delete))]
    [TestCase(nameof(UsersController.UpdateRole))]
    [TestCase(nameof(UsersController.ChangePassword))]
    public async Task EveryEndpointDeniesAccessForUnauthenticatedUsers(string actionName)
    {
        var isAuthorized = await IsAuthorized(actionName, new ClaimsPrincipal());

        Assert.That(isAuthorized, Is.False);
    }

    [TestCase(nameof(UsersController.GetAll))]
    [TestCase(nameof(UsersController.UpdateRole))]
    public async Task AdminEndpointsDenyAccessForUsersWithUserRole(string actionName)
    {
        var isAuthorized = await IsAuthorized(actionName, CreatePrincipal("1", "User"));

        Assert.That(isAuthorized, Is.False);
    }

    [TestCase(nameof(UsersController.GetAll))]
    [TestCase(nameof(UsersController.UpdateRole))]
    public async Task AdminEndpointsAllowAccessForUsersWithAdminRole(string actionName)
    {
        var isAuthorized = await IsAuthorized(actionName, CreatePrincipal("1", "Admin"));

        Assert.That(isAuthorized, Is.True);
    }

    [Test]
    public void GetAllReturnsEveryUserForAdmin()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var admin = CreateUser(repository, "admin", "admin@example.com", "Admin");
        CreateUser(repository, "regular-user", "user@example.com");
        var controller = CreateController(repository, admin.UserID.ToString(), admin.Role);

        var result = controller.GetAll();

        var okResult = result.Result as OkObjectResult;
        var users = (okResult?.Value as IEnumerable<UserResponse>)?.ToList();
        Assert.Multiple(() =>
        {
            Assert.That(okResult, Is.Not.Null);
            Assert.That(users, Has.Count.EqualTo(2));
            Assert.That(users?.Select(user => user.Username),
                Is.EquivalentTo(new[] { "admin", "regular-user" }));
        });
    }

    [Test]
    public void GetByIdReturnsCurrentUserWhenIdHeaderIsOmitted()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var user = CreateUser(repository, "current-user", "current@example.com");
        var controller = CreateController(repository, user.UserID.ToString(), user.Role);

        var result = controller.GetById(null);

        var okResult = result.Result as OkObjectResult;
        var response = okResult?.Value as UserResponse;
        Assert.Multiple(() =>
        {
            Assert.That(okResult, Is.Not.Null);
            Assert.That(response?.UserId, Is.EqualTo(user.UserID));
            Assert.That(response?.Username, Is.EqualTo(user.Username));
        });
    }

    [Test]
    public void GetByIdAllowsAdminToRequestAnotherUser()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var admin = CreateUser(repository, "admin", "admin@example.com", "Admin");
        var requestedUser = CreateUser(repository, "requested-user", "requested@example.com");
        var controller = CreateController(repository, admin.UserID.ToString(), admin.Role);

        var result = controller.GetById(requestedUser.UserID);

        var response = (result.Result as OkObjectResult)?.Value as UserResponse;
        Assert.That(response?.UserId, Is.EqualTo(requestedUser.UserID));
    }

    [Test]
    public void GetByIdForAnotherUserIsForbiddenForUserRole()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var currentUser = CreateUser(repository, "current-user", "current@example.com");
        var otherUser = CreateUser(repository, "other-user", "other@example.com");
        var controller = CreateController(repository, currentUser.UserID.ToString(), currentUser.Role);

        var result = controller.GetById(otherUser.UserID);

        Assert.That(result.Result, Is.TypeOf<ForbidResult>());
    }

    [Test]
    public void GetByIdReturnsNotFoundForUnknownUser()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var admin = CreateUser(repository, "admin", "admin@example.com", "Admin");
        var controller = CreateController(repository, admin.UserID.ToString(), admin.Role);

        var result = controller.GetById(999);

        Assert.That(result.Result, Is.TypeOf<NotFoundResult>());
    }

    [Test]
    public void GetByIdRejectsMalformedSubjectClaim()
    {
        using var connection = CreateDatabase();
        var controller = CreateController(new UserRepository(connection), "not-a-number", "User");

        var result = controller.GetById(null);

        Assert.That(result.Result, Is.TypeOf<UnauthorizedResult>());
    }

    [Test]
    public void DeleteRemovesCurrentUserWhenIdHeaderIsOmitted()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var user = CreateUser(repository, "current-user", "current@example.com");
        var controller = CreateController(repository, user.UserID.ToString(), user.Role);

        var result = controller.Delete(null);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.TypeOf<NoContentResult>());
            Assert.That(repository.GetById(user.UserID), Is.Null);
            Assert.That(
                controller.Response.Headers.SetCookie.ToString(),
                Does.StartWith($"{AuthenticationCookie.Name}="));
        });
    }

    [Test]
    public void DeleteAllowsAdminToRemoveAnotherUser()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var admin = CreateUser(repository, "admin", "admin@example.com", "Admin");
        var otherUser = CreateUser(repository, "other-user", "other@example.com");
        var controller = CreateController(repository, admin.UserID.ToString(), admin.Role);

        var result = controller.Delete(otherUser.UserID);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.TypeOf<NoContentResult>());
            Assert.That(repository.GetById(otherUser.UserID), Is.Null);
            Assert.That(repository.GetById(admin.UserID), Is.Not.Null);
        });
    }

    [Test]
    public void DeleteAnotherUserIsForbiddenForUserRole()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var currentUser = CreateUser(repository, "current-user", "current@example.com");
        var otherUser = CreateUser(repository, "other-user", "other@example.com");
        var controller = CreateController(repository, currentUser.UserID.ToString(), currentUser.Role);

        var result = controller.Delete(otherUser.UserID);

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.TypeOf<ForbidResult>());
            Assert.That(repository.GetById(otherUser.UserID), Is.Not.Null);
        });
    }

    [Test]
    public void DeleteReturnsNotFoundForUnknownUser()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var admin = CreateUser(repository, "admin", "admin@example.com", "Admin");
        var controller = CreateController(repository, admin.UserID.ToString(), admin.Role);

        var result = controller.Delete(999);

        Assert.That(result, Is.TypeOf<NotFoundResult>());
    }

    [Test]
    public void DeleteRejectsMalformedSubjectClaim()
    {
        using var connection = CreateDatabase();
        var controller = CreateController(new UserRepository(connection), "not-a-number", "User");

        var result = controller.Delete(null);

        Assert.That(result, Is.TypeOf<UnauthorizedResult>());
    }

    [TestCase("Admin")]
    [TestCase("User")]
    public void UpdateRoleAcceptsValidRole(string newRole)
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var admin = CreateUser(repository, "admin", "admin@example.com", "Admin");
        var user = CreateUser(repository, "target-user", "target@example.com");
        var controller = CreateController(repository, admin.UserID.ToString(), admin.Role);

        var result = controller.UpdateRole(new UpdateUserRoleRequest(user.UserID, newRole));

        var response = (result.Result as OkObjectResult)?.Value as UserResponse;
        Assert.Multiple(() =>
        {
            Assert.That(response?.Role, Is.EqualTo(newRole));
            Assert.That(repository.GetById(user.UserID)?.Role, Is.EqualTo(newRole));
        });
    }

    [TestCase("")]
    [TestCase("Administrator")]
    [TestCase("admin")]
    public void UpdateRoleRejectsInvalidRole(string invalidRole)
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var admin = CreateUser(repository, "admin", "admin@example.com", "Admin");
        var user = CreateUser(repository, "target-user", "target@example.com");
        var controller = CreateController(repository, admin.UserID.ToString(), admin.Role);

        var result = controller.UpdateRole(new UpdateUserRoleRequest(user.UserID, invalidRole));

        Assert.Multiple(() =>
        {
            Assert.That(result.Result, Is.TypeOf<BadRequestObjectResult>());
            Assert.That(repository.GetById(user.UserID)?.Role, Is.EqualTo("User"));
        });
    }

    [Test]
    public void UpdateRoleRejectsRoleThatExceedsMaximumLength()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var admin = CreateUser(repository, "admin", "admin@example.com", "Admin");
        var user = CreateUser(repository, "target-user", "target@example.com");
        var controller = CreateController(repository, admin.UserID.ToString(), admin.Role);

        var result = controller.UpdateRole(new UpdateUserRoleRequest(
            user.UserID,
            new string('a', UserInputLimits.RoleMaxLength + 1)));

        Assert.Multiple(() =>
        {
            Assert.That(result.Result, Is.TypeOf<BadRequestObjectResult>());
            Assert.That(repository.GetById(user.UserID)?.Role, Is.EqualTo("User"));
        });
    }

    [Test]
    public void UpdateRoleReturnsNotFoundForUnknownUser()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var admin = CreateUser(repository, "admin", "admin@example.com", "Admin");
        var controller = CreateController(repository, admin.UserID.ToString(), admin.Role);

        var result = controller.UpdateRole(new UpdateUserRoleRequest(999, "Admin"));

        Assert.That(result.Result, Is.TypeOf<NotFoundResult>());
    }

    [Test]
    public void ChangePasswordChangesOnlyTheUserIdentifiedByTheToken()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var currentUser = CreateUser(repository, "current-user", "current@example.com");
        var otherUser = CreateUser(repository, "other-user", "other@example.com");
        var controller = CreateController(repository, currentUser.UserID.ToString(), currentUser.Role);

        var result = controller.ChangePassword(new ChangePasswordRequest("password", "new-password"));

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.TypeOf<NoContentResult>());
            Assert.That(repository.GetByCredentials(currentUser.Username, "password"), Is.Null);
            Assert.That(repository.GetByCredentials(currentUser.Username, "new-password"), Is.Not.Null);
            Assert.That(repository.GetByCredentials(otherUser.Username, "password"), Is.Not.Null);
        });
    }

    [Test]
    public void ChangePasswordRejectsAnIncorrectOldPassword()
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var user = CreateUser(repository, "test-user", "test@example.com");
        var controller = CreateController(repository, user.UserID.ToString(), user.Role);

        var result = controller.ChangePassword(new ChangePasswordRequest("wrong-password", "new-password"));

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.TypeOf<BadRequestObjectResult>());
            Assert.That(repository.GetByCredentials(user.Username, "password"), Is.Not.Null);
            Assert.That(repository.GetByCredentials(user.Username, "new-password"), Is.Null);
        });
    }

    [TestCase("", "new-password")]
    [TestCase(" ", "new-password")]
    [TestCase("password", "")]
    [TestCase("password", " ")]
    public void ChangePasswordRejectsMissingOrWhitespacePasswords(
        string oldPassword,
        string newPassword)
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var user = CreateUser(repository, "test-user", "test@example.com");
        var controller = CreateController(repository, user.UserID.ToString(), user.Role);

        var result = controller.ChangePassword(new ChangePasswordRequest(oldPassword, newPassword));

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.TypeOf<BadRequestObjectResult>());
            Assert.That(repository.GetByCredentials(user.Username, "password"), Is.Not.Null);
        });
    }

    [TestCase(true)]
    [TestCase(false)]
    public void ChangePasswordRejectsOverlongOldOrNewPassword(bool overlongOldPassword)
    {
        using var connection = CreateDatabase();
        var repository = new UserRepository(connection);
        var user = CreateUser(repository, "test-user", "test@example.com");
        var controller = CreateController(repository, user.UserID.ToString(), user.Role);
        var overlongPassword = new string('a', UserInputLimits.PasswordMaxLength + 1);

        var result = controller.ChangePassword(new ChangePasswordRequest(
            overlongOldPassword ? overlongPassword : "password",
            overlongOldPassword ? "new-password" : overlongPassword));

        Assert.Multiple(() =>
        {
            Assert.That(result, Is.TypeOf<BadRequestObjectResult>());
            Assert.That(repository.GetByCredentials(user.Username, "password"), Is.Not.Null);
        });
    }

    [Test]
    public void ChangePasswordRejectsMalformedSubjectClaim()
    {
        using var connection = CreateDatabase();
        var controller = CreateController(new UserRepository(connection), "not-a-number", "User");

        var result = controller.ChangePassword(new ChangePasswordRequest("password", "new-password"));

        Assert.That(result, Is.TypeOf<UnauthorizedResult>());
    }

    private static async Task<bool> IsAuthorized(string actionName, ClaimsPrincipal principal)
    {
        var action = typeof(UsersController).GetMethod(
            actionName,
            BindingFlags.Instance | BindingFlags.Public);
        Assert.That(action, Is.Not.Null, $"Could not find action '{actionName}'.");

        var authorizeData = typeof(UsersController)
            .GetCustomAttributes<AuthorizeAttribute>(true)
            .Concat(action!.GetCustomAttributes<AuthorizeAttribute>(true))
            .Cast<IAuthorizeData>()
            .ToArray();
        var policyProvider = new DefaultAuthorizationPolicyProvider(
            Options.Create(new AuthorizationOptions()));
        var policy = await AuthorizationPolicy.CombineAsync(policyProvider, authorizeData);
        Assert.That(policy, Is.Not.Null, $"Action '{actionName}' has no authorization policy.");

        var context = new AuthorizationHandlerContext(policy!.Requirements, principal, null);
        await new PassThroughAuthorizationHandler().HandleAsync(context);
        return context.HasSucceeded;
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

    private static UsersController CreateController(
        UserRepository repository,
        string subject,
        string role)
    {
        return new UsersController(repository)
        {
            ControllerContext = new ControllerContext
            {
                HttpContext = new DefaultHttpContext
                {
                    User = CreatePrincipal(subject, role)
                }
            }
        };
    }

    private static ClaimsPrincipal CreatePrincipal(string subject, string role)
    {
        var identity = new ClaimsIdentity(
            [
                new Claim(JwtRegisteredClaimNames.Sub, subject),
                new Claim(ClaimTypes.Role, role)
            ],
            "TestAuthentication");
        return new ClaimsPrincipal(identity);
    }
}
