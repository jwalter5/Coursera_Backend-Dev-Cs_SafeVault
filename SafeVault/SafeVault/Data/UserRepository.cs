using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using SafeVault.Models;

namespace SafeVault.Data;

public class UserRepository
{
    private readonly SqliteConnection _connection;
    private readonly PasswordHasher<User> _passwordHasher = new();

    public UserRepository(SqliteConnection connection)
    {
        _connection = connection;
    }

    public int Create(User user)
    {
        var passwordHash = _passwordHasher.HashPassword(user, user.Password);

        using var command = _connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO Users (Username, Email, Password, Role)
            VALUES ($username, $email, $password, $role);

            SELECT last_insert_rowid();
            """;
        AddUserParameters(command, user, passwordHash);

        return Convert.ToInt32(command.ExecuteScalar());
    }

    public User? GetById(int userId)
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            """
            SELECT UserID, Username, Email, Password, Role
            FROM Users
            WHERE UserID = $userId;
            """;
        command.Parameters.AddWithValue("$userId", userId);

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadUser(reader) : null;
    }

    public User? GetByCredentials(string username, string password)
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            """
            SELECT UserID, Username, Email, Password, Role
            FROM Users
            WHERE Username = $username;
            """;
        command.Parameters.AddWithValue("$username", username);

        using var reader = command.ExecuteReader();
        if (!reader.Read())
        {
            return null;
        }

        var user = ReadUser(reader);
        var verificationResult = _passwordHasher.VerifyHashedPassword(user, user.Password, password);

        return verificationResult == PasswordVerificationResult.Failed ? null : user;
    }

    public User? GetByUsername(string username)
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT UserID, Username, Email, Password, Role FROM Users WHERE Username = $username;";
        command.Parameters.AddWithValue("$username", username);

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadUser(reader) : null;
    }

    public User? GetByEmail(string email)
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            "SELECT UserID, Username, Email, Password, Role FROM Users WHERE Email = $email;";
        command.Parameters.AddWithValue("$email", email);

        using var reader = command.ExecuteReader();
        return reader.Read() ? ReadUser(reader) : null;
    }

    public IReadOnlyList<User> GetAll()
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            """
            SELECT UserID, Username, Email, Password, Role
            FROM Users
            ORDER BY UserID;
            """;

        using var reader = command.ExecuteReader();
        var users = new List<User>();

        while (reader.Read())
        {
            users.Add(ReadUser(reader));
        }

        return users;
    }

    public bool UpdateRole(int userId, string role)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "UPDATE Users SET Role = $role WHERE UserID = $userId;";
        command.Parameters.AddWithValue("$role", role);
        command.Parameters.AddWithValue("$userId", userId);

        return command.ExecuteNonQuery() == 1;
    }

    public bool ChangePassword(int userId, string oldPassword, string newPassword)
    {
        var user = GetById(userId);
        if (user is null)
        {
            return false;
        }

        var verificationResult = _passwordHasher.VerifyHashedPassword(user, user.Password, oldPassword);
        if (verificationResult == PasswordVerificationResult.Failed)
        {
            return false;
        }

        var passwordHash = _passwordHasher.HashPassword(user, newPassword);

        using var command = _connection.CreateCommand();
        command.CommandText = "UPDATE Users SET Password = $password WHERE UserID = $userId;";
        command.Parameters.AddWithValue("$password", passwordHash);
        command.Parameters.AddWithValue("$userId", userId);

        return command.ExecuteNonQuery() == 1;
    }

    public bool Delete(int userId)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "DELETE FROM Users WHERE UserID = $userId;";
        command.Parameters.AddWithValue("$userId", userId);

        return command.ExecuteNonQuery() == 1;
    }

    private static void AddUserParameters(SqliteCommand command, User user, string passwordHash)
    {
        command.Parameters.AddWithValue("$username", user.Username);
        command.Parameters.AddWithValue("$email", user.Email);
        command.Parameters.AddWithValue("$password", passwordHash);
        command.Parameters.AddWithValue("$role", user.Role);
    }

    private static User ReadUser(SqliteDataReader reader)
    {
        return new User
        {
            UserID = reader.GetInt32(0),
            Username = reader.GetString(1),
            Email = reader.GetString(2),
            Password = reader.GetString(3),
            Role = reader.GetString(4)
        };
    }
}
