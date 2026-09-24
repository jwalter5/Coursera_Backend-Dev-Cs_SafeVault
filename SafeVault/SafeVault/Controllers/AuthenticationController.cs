using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using SafeVault.Utilities;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("")]
    public class AuthenticationController : ControllerBase
    {
        private readonly SqliteConnection _connection;

        public AuthenticationController(SqliteConnection connection)
        {
            _connection = connection;
        }

        [HttpPost]
        [Route("submit")]
        public IActionResult CreateUser([FromForm] SubmitRequest request)
        {
            if (!IsValidRequest(request))
            {
                return BadRequest("Username or email contains invalid characters.");
            }

            using var command = _connection.CreateCommand();
            command.CommandText =
                """
                INSERT INTO Users (Username, Email)
                VALUES ($username, $email);
                """;
            command.Parameters.AddWithValue("$username", request.Username);
            command.Parameters.AddWithValue("$email", request.Email);
            command.ExecuteNonQuery();

            return Ok();
        }

        [HttpPost]
        [Route("login")]
        public IActionResult Login([FromForm] SubmitRequest request)
        {
            if (!IsValidRequest(request))
            {
                return Ok(false);
            }

            using var command = _connection.CreateCommand();
            command.CommandText =
                """
                SELECT EXISTS (
                    SELECT 1
                    FROM Users
                    WHERE Username = $username AND Email = $email
                );
                """;
            command.Parameters.AddWithValue("$username", request.Username);
            command.Parameters.AddWithValue("$email", request.Email);

            var userExists = Convert.ToInt32(command.ExecuteScalar()) == 1;

            return Ok(userExists);
        }

        private static bool IsValidRequest(SubmitRequest request)
        {
            return ValidationHelpers.IsValidInput(request.Username, "-_.")
                && ValidationHelpers.IsValidInput(request.Email, "@._+-")
                && ValidationHelpers.IsValidXSSInput(request.Username)
                && ValidationHelpers.IsValidXSSInput(request.Email);
        }
    }

    public class SubmitRequest
    {
        public required string Username { get; set; }
        public required string Email { get; set; }
    }
}
