using Microsoft.Data.Sqlite;
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

        Assert.That(repository.UpdateRole(user.UserID, "Admin"), Is.True);
        Assert.That(repository.GetById(user.UserID)?.Role, Is.EqualTo("Admin"));
        Assert.That(repository.GetById(user.UserID)?.Email, Is.EqualTo("test@example.com"));
        Assert.That(repository.GetByCredentials("test-user", "password"), Is.Not.Null);

        Assert.That(repository.ChangePassword(user.UserID, "wrong-password", "new-password"), Is.False);
        Assert.That(repository.GetByCredentials("test-user", "password"), Is.Not.Null);

        Assert.That(repository.ChangePassword(user.UserID, "password", "new-password"), Is.True);
        Assert.That(repository.GetByCredentials("test-user", "password"), Is.Null);
        Assert.That(repository.GetByCredentials("test-user", "new-password"), Is.Not.Null);

        Assert.That(repository.Delete(user.UserID), Is.True);
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
