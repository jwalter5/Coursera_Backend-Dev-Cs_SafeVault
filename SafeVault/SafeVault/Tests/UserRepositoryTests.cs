using Microsoft.Data.Sqlite;
using NUnit.Framework;
using SafeVault.Data;
using SafeVault.Models;

[TestFixture]
public class UserRepositoryTests
{
    [Test]
    public void CrudOperationsPersistUserChanges()
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

        user.Email = "updated@example.com";
        Assert.That(repository.Update(user), Is.True);
        Assert.That(repository.GetById(user.UserID)?.Email, Is.EqualTo("updated@example.com"));
        Assert.That(repository.GetByCredentials("test-user", "password"), Is.Not.Null);

        Assert.That(repository.Delete(user.UserID), Is.True);
        Assert.That(repository.GetById(user.UserID), Is.Null);
    }
}
