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
        if (user.Email.Length > UserInputLimits.EmailMaxLength)
        {
            throw new ArgumentException(
                $"Email must not exceed {UserInputLimits.EmailMaxLength} characters.",
                nameof(user));
        }

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

        User user;
        using (var reader = command.ExecuteReader())
        {
            if (!reader.Read())
                return null;

            user = ReadUser(reader);
        }

        return VerifyPassword(user, password) ? user : null;
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
            users.Add(ReadUser(reader));

        return users;
    }

    public UserMutationResult UpdateRole(int userId, string role)
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            """
            UPDATE Users
            SET Role = $role
            WHERE UserID = $userId
              AND (
                  Role <> 'Admin'
                  OR $role = 'Admin'
                  OR EXISTS (
                      SELECT 1
                      FROM Users AS OtherAdmins
                      WHERE OtherAdmins.Role = 'Admin'
                        AND OtherAdmins.UserID <> $userId
                  )
              );
            """;
        command.Parameters.AddWithValue("$role", role);
        command.Parameters.AddWithValue("$userId", userId);

        if (command.ExecuteNonQuery() == 1)
            return UserMutationResult.Success;

        return GetById(userId) is null
            ? UserMutationResult.NotFound
            : UserMutationResult.LastAdministrator;
    }

    public bool ChangePassword(int userId, string oldPassword, string newPassword)
    {
        if (newPassword.Length > UserInputLimits.PasswordMaxLength)
            return false;

        var user = GetById(userId);
        if (user is null)
            return false;

        var verificationResult = _passwordHasher.VerifyHashedPassword(user, user.Password, oldPassword);
        if (verificationResult == PasswordVerificationResult.Failed)
            return false;

        var passwordHash = _passwordHasher.HashPassword(user, newPassword);

        using var command = _connection.CreateCommand();
        command.CommandText = "UPDATE Users SET Password = $password WHERE UserID = $userId;";
        command.Parameters.AddWithValue("$password", passwordHash);
        command.Parameters.AddWithValue("$userId", userId);

        return command.ExecuteNonQuery() == 1;
    }

    public bool VerifyPassword(int userId, string password)
    {
        var user = GetById(userId);
        return user is not null && VerifyPassword(user, password);
    }

    public UserMutationResult Delete(int userId)
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            """
            DELETE FROM Users
            WHERE UserID = $userId
              AND (
                  Role <> 'Admin'
                  OR EXISTS (
                      SELECT 1
                      FROM Users AS OtherAdmins
                      WHERE OtherAdmins.Role = 'Admin'
                        AND OtherAdmins.UserID <> $userId
                  )
              );
            """;
        command.Parameters.AddWithValue("$userId", userId);

        if (command.ExecuteNonQuery() == 1)
            return UserMutationResult.Success;

        return GetById(userId) is null
            ? UserMutationResult.NotFound
            : UserMutationResult.LastAdministrator;
    }

    private bool VerifyPassword(User user, string password)
    {
        var verificationResult = _passwordHasher.VerifyHashedPassword(user, user.Password, password);
        if (verificationResult == PasswordVerificationResult.Failed)
            return false;

        if (verificationResult == PasswordVerificationResult.SuccessRehashNeeded)
        {
            var previousHash = user.Password;
            var upgradedHash = _passwordHasher.HashPassword(user, password);

            if (UpdatePasswordHash(user.UserID, previousHash, upgradedHash))
                user.Password = upgradedHash;
        }

        return true;
    }

    private bool UpdatePasswordHash(int userId, string previousHash, string upgradedHash)
    {
        using var command = _connection.CreateCommand();
        command.CommandText =
            "UPDATE Users SET Password = $upgradedHash WHERE UserID = $userId AND Password = $previousHash;";
        command.Parameters.AddWithValue("$upgradedHash", upgradedHash);
        command.Parameters.AddWithValue("$userId", userId);
        command.Parameters.AddWithValue("$previousHash", previousHash);

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

public enum UserMutationResult
{
    Success,
    NotFound,
    LastAdministrator
}
