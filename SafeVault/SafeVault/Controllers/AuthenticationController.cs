using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;
using SafeVault.Utilities;

namespace SafeVault.Controllers;

[ApiController]
[Route("api/auth")]
public class AuthenticationController : ControllerBase
{
    private const string DefaultRole = "User";
    private readonly UserRepository _userRepository;
    private readonly JwtTokenService _jwtTokenService;

    public AuthenticationController(UserRepository userRepository, JwtTokenService jwtTokenService)
    {
        _userRepository = userRepository;
        _jwtTokenService = jwtTokenService;
    }

    [AllowAnonymous]
    [HttpPost("register")]
    public IActionResult CreateUser([FromBody] RegistrationRequest request)
    {
        if (!IsValidRegistrationRequest(request))
            return BadRequest(new { message = "The registration information is invalid." });

        if (_userRepository.GetByUsername(request.Username) is not null || _userRepository.GetByEmail(request.Email) is not null)
            return Conflict(new { message = "The username or email address is already registered." });

        var user = new User
        {
            Username = request.Username,
            Email = request.Email,
            Password = request.Password,
            Role = DefaultRole
        };
        user.UserID = _userRepository.Create(user);

        return Ok(CreateAuthenticationResponse(user));
    }

    [AllowAnonymous]
    [HttpPost("login")]
    public IActionResult Login([FromBody] LoginRequest request)
    {
        if (!IsValidLoginRequest(request))
            return Unauthorized(new { message = "Invalid username or password." });

        var user = _userRepository.GetByCredentials(request.Username, request.Password);
        return user is null
            ? Unauthorized(new { message = "Invalid username or password." })
            : Ok(CreateAuthenticationResponse(user));
    }

    private AuthenticationResponse CreateAuthenticationResponse(User user)
    {
        var token = _jwtTokenService.CreateToken(user);
        return new AuthenticationResponse(token.Token, token.ExpiresAt, UserResponse.FromUser(user));
    }

    private static bool IsValidRegistrationRequest(RegistrationRequest request)
    {
        return !string.IsNullOrWhiteSpace(request.Password)
            && ValidationHelpers.IsValidInput(request.Username, "-_.")
            && ValidationHelpers.IsValidInput(request.Email, "@._+-")
            && ValidationHelpers.IsValidXSSInput(request.Username)
            && ValidationHelpers.IsValidXSSInput(request.Email);
    }

    private static bool IsValidLoginRequest(LoginRequest request)
    {
        return !string.IsNullOrWhiteSpace(request.Password)
            && ValidationHelpers.IsValidInput(request.Username, "-_.")
            && ValidationHelpers.IsValidXSSInput(request.Username);
    }
}

public sealed class RegistrationRequest
{
    public required string Username { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
}

public sealed class LoginRequest
{
    public required string Username { get; set; }
    public required string Password { get; set; }
}

public sealed record AuthenticationResponse(string Token, DateTime ExpiresAt, UserResponse User);

public sealed record UserResponse(int UserId, string Username, string Email, string Role)
{
    public static UserResponse FromUser(User user) =>
        new(user.UserID, user.Username, user.Email, user.Role);
}
