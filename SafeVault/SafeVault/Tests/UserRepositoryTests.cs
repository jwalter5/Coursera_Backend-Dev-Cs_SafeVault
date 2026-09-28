using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Models;

[TestFixture]
public class UserRepositoryTests
{
    [Test]
    public void SqlInjectionPayloadsAreTreatedAsLiteralValues()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        CreateUsersTable(connection);

        var repository = new UserRepository(connection);
        var existingUser = new User
        {
            Username = "existing-user",
            Email = "existing@example.com",
            Password = "password",
            Role = "User"
        };
        existingUser.UserID = repository.Create(existingUser);

        const string maliciousUsername = "' OR 1=1 --";
        const string maliciousEmail = "attacker@example.com' OR 1=1 --";

        Assert.Multiple(() =>
        {
            Assert.That(repository.GetByUsername(maliciousUsername), Is.Null);
            Assert.That(repository.GetByEmail(maliciousEmail), Is.Null);
            Assert.That(repository.GetByCredentials(maliciousUsername, "password"), Is.Null);
        });

        var payloadUser = new User
        {
            Username = maliciousUsername,
            Email = maliciousEmail,
            Password = "payload-password",
            Role = "User"
        };
        payloadUser.UserID = repository.Create(payloadUser);

        Assert.Multiple(() =>
        {
            Assert.That(repository.GetByUsername(maliciousUsername)?.UserID, Is.EqualTo(payloadUser.UserID));
            Assert.That(repository.GetByEmail(maliciousEmail)?.UserID, Is.EqualTo(payloadUser.UserID));
            Assert.That(repository.GetById(existingUser.UserID)?.Username, Is.EqualTo(existingUser.Username));
            Assert.That(repository.GetAll(), Has.Count.EqualTo(2));
        });
    }

    [Test]
    public void CrudOperationsPersistRoleChanges()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        CreateUsersTable(connection);

        var repository = new UserRepository(connection);
        var user = new User
        {
            Username = "test-user",
            Email = "test@example.com",
            Password = "password",
            Role = "User"
        };

        user.UserID = repository.Create(user);

        using (var command = connection.CreateCommand())
        {
            command.CommandText = "SELECT Password FROM Users WHERE UserID = $userId;";
            command.Parameters.AddWithValue("$userId", user.UserID);

            var storedPassword = (string?)command.ExecuteScalar();
            Assert.That(storedPassword, Is.Not.Null.And.Not.EqualTo("password"));
        }

        Assert.That(repository.GetByCredentials("test-user", "password"), Is.Not.Null);
        Assert.That(repository.GetByCredentials("test-user", "wrong-password"), Is.Null);
        Assert.That(repository.GetById(user.UserID)?.Username, Is.EqualTo("test-user"));
        Assert.That(repository.GetAll(), Has.Count.EqualTo(1));

        Assert.That(repository.UpdateRole(user.UserID, "Admin"), Is.EqualTo(UserMutationResult.Success));
        Assert.That(repository.GetById(user.UserID)?.Role, Is.EqualTo("Admin"));
        Assert.That(repository.GetById(user.UserID)?.Email, Is.EqualTo("test@example.com"));
        Assert.That(repository.GetByCredentials("test-user", "password"), Is.Not.Null);

        Assert.That(repository.ChangePassword(user.UserID, "wrong-password", "new-password"), Is.False);
        Assert.That(repository.GetByCredentials("test-user", "password"), Is.Not.Null);

        Assert.That(repository.ChangePassword(user.UserID, "password", "new-password"), Is.True);
        Assert.That(repository.GetByCredentials("test-user", "password"), Is.Null);
        Assert.That(repository.GetByCredentials("test-user", "new-password"), Is.Not.Null);

        repository.Create(new User
        {
            Username = "backup-admin",
            Email = "backup-admin@example.com",
            Password = "password",
            Role = "Admin"
        });
        Assert.That(repository.Delete(user.UserID), Is.EqualTo(UserMutationResult.Success));
        Assert.That(repository.GetById(user.UserID), Is.Null);
    }

    [TestCase(nameof(User.Username))]
    [TestCase(nameof(User.Email))]
    [TestCase(nameof(User.Role))]
    public void CreateRejectsOverlongValues(string overlongProperty)
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        CreateUsersTable(connection);
        var repository = new UserRepository(connection);
        var user = new User
        {
            Username = "valid-user",
            Email = "user@example.com",
            Password = "password",
            Role = "User"
        };

        switch (overlongProperty)
        {
            case nameof(User.Username):
                user.Username = new string('a', UserInputLimits.UsernameMaxLength + 1);
                break;
            case nameof(User.Email):
                user.Email = new string('a', UserInputLimits.EmailMaxLength + 1);
                break;
            case nameof(User.Role):
                user.Role = new string('a', UserInputLimits.RoleMaxLength + 1);
                break;
        }

        if (overlongProperty == nameof(User.Email))
        {
            var exception = Assert.Throws<ArgumentException>(() => repository.Create(user));
            Assert.That(exception!.ParamName, Is.EqualTo("user"));
        }
        else
        {
            Assert.Throws<SqliteException>(() => repository.Create(user));
        }

        Assert.That(repository.GetAll(), Is.Empty);
    }

    [Test]
    public void ChangePasswordRejectsOverlongNewPassword()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        CreateUsersTable(connection);
        var repository = new UserRepository(connection);
        var user = new User
        {
            Username = "test-user",
            Email = "test@example.com",
            Password = "password",
            Role = "User"
        };
        user.UserID = repository.Create(user);
        var overlongPassword = new string('a', UserInputLimits.PasswordMaxLength + 1);

        var changed = repository.ChangePassword(user.UserID, "password", overlongPassword);

        Assert.Multiple(() =>
        {
            Assert.That(changed, Is.False);
            Assert.That(repository.GetByCredentials(user.Username, "password"), Is.Not.Null);
            Assert.That(repository.GetByCredentials(user.Username, overlongPassword), Is.Null);
        });
    }

    [Test]
    public void GetByCredentialsUpgradesPasswordHashWhenRehashIsNeeded()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        CreateUsersTable(connection);

        const string password = "password";
        var user = new User
        {
            Username = "legacy-user",
            Email = "legacy@example.com",
            Password = password,
            Role = "User"
        };
        var legacyHasher = new PasswordHasher<User>(Options.Create(new PasswordHasherOptions
        {
            IterationCount = 10_000
        }));
        var legacyHash = legacyHasher.HashPassword(user, password);

        using (var command = connection.CreateCommand())
        {
            command.CommandText =
                """
                INSERT INTO Users (Username, Email, Password, Role)
                VALUES ($username, $email, $password, $role);
                """;
            command.Parameters.AddWithValue("$username", user.Username);
            command.Parameters.AddWithValue("$email", user.Email);
            command.Parameters.AddWithValue("$password", legacyHash);
            command.Parameters.AddWithValue("$role", user.Role);
            command.ExecuteNonQuery();
        }

        var authenticatedUser = new UserRepository(connection)
            .GetByCredentials(user.Username, password);

        using var hashCommand = connection.CreateCommand();
        hashCommand.CommandText = "SELECT Password FROM Users WHERE Username = $username;";
        hashCommand.Parameters.AddWithValue("$username", user.Username);
        var upgradedHash = (string?)hashCommand.ExecuteScalar();

        var currentHasher = new PasswordHasher<User>();
        Assert.Multiple(() =>
        {
            Assert.That(authenticatedUser, Is.Not.Null);
            Assert.That(upgradedHash, Is.Not.Null.And.Not.EqualTo(legacyHash));
            Assert.That(
                currentHasher.VerifyHashedPassword(user, upgradedHash!, password),
                Is.EqualTo(PasswordVerificationResult.Success));
        });
    }

    [Test]
    public void FinalAdministratorCannotBeDemotedOrDeleted()
    {
        using var connection = new SqliteConnection("Data Source=:memory:");
        connection.Open();
        CreateUsersTable(connection);
        var repository = new UserRepository(connection);
        var admin = new User
        {
            Username = "admin",
            Email = "admin@example.com",
            Password = "password",
            Role = "Admin"
        };
        admin.UserID = repository.Create(admin);

        var demoteResult = repository.UpdateRole(admin.UserID, "User");
        var deleteResult = repository.Delete(admin.UserID);

        Assert.Multiple(() =>
        {
            Assert.That(demoteResult, Is.EqualTo(UserMutationResult.LastAdministrator));
            Assert.That(deleteResult, Is.EqualTo(UserMutationResult.LastAdministrator));
            Assert.That(repository.GetById(admin.UserID)?.Role, Is.EqualTo("Admin"));
        });
    }

    private static void CreateUsersTable(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText =
            $"""
            CREATE TABLE Users (
                UserID INTEGER PRIMARY KEY AUTOINCREMENT,
                Username TEXT NOT NULL
                    CHECK (length(Username) BETWEEN 1 AND {UserInputLimits.UsernameMaxLength}),
                Email TEXT NOT NULL
                    CHECK (length(Email) BETWEEN 1 AND {UserInputLimits.EmailMaxLength}),
                Password TEXT NOT NULL
                    CHECK (length(Password) BETWEEN 1 AND {UserInputLimits.PasswordHashMaxLength}),
                Role TEXT NOT NULL
                    CHECK (length(Role) BETWEEN 1 AND {UserInputLimits.RoleMaxLength})
            );
            """;
        command.ExecuteNonQuery();
    }
}
