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

    public bool Update(User user)
    {
        // Objects returned by this repository contain the persisted password hash. Preserve
        // that value when only another user property is changed; otherwise hash the new password.
        var storedPasswordHash = GetPasswordHash(user.UserID);
        var passwordHash = storedPasswordHash is not null && storedPasswordHash == user.Password
            ? storedPasswordHash
            : _passwordHasher.HashPassword(user, user.Password);

        using var command = _connection.CreateCommand();
        command.CommandText =
            """
            UPDATE Users
            SET Username = $username,
                Email = $email,
                Password = $password,
                Role = $role
            WHERE UserID = $userId;
            """;
        AddUserParameters(command, user, passwordHash);
        command.Parameters.AddWithValue("$userId", user.UserID);

        return command.ExecuteNonQuery() == 1;
    }

    public bool Delete(int userId)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "DELETE FROM Users WHERE UserID = $userId;";
        command.Parameters.AddWithValue("$userId", userId);

        return command.ExecuteNonQuery() == 1;
    }

    private string? GetPasswordHash(int userId)
    {
        using var command = _connection.CreateCommand();
        command.CommandText = "SELECT Password FROM Users WHERE UserID = $userId;";
        command.Parameters.AddWithValue("$userId", userId);

        return command.ExecuteScalar() as string;
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
