using Microsoft.AspNetCore.Mvc;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Utilities;

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("")]
    public class AuthenticationController : ControllerBase
    {
        private const string DefaultRole = "User";
        private const string IndexPage = "/index.html";
        private const string LoginPage = "/login.html";
        private const string RegisterPage = "/register.html";
        private readonly UserRepository _userRepository;

        public AuthenticationController(UserRepository userRepository)
        {
            _userRepository = userRepository;
        }

        [HttpPost]
        [Route("submit")]
        public IActionResult CreateUser([FromForm] RegistrationRequest request)
        {
            if (!IsValidRegistrationRequest(request))
            {
                return Redirect(RegisterPage);
            }

            _userRepository.Create(new User
            {
                Username = request.Username,
                Email = request.Email,
                Password = request.Password,
                Role = DefaultRole
            });

            return Redirect(IndexPage);
        }

        [HttpPost]
        [Route("login")]
        public IActionResult Login([FromForm] LoginRequest request)
        {
            if (!IsValidLoginRequest(request))
            {
                return Redirect(LoginPage);
            }

            var userExists = _userRepository.GetByCredentials(request.Username, request.Password) is not null;

            return Redirect(userExists ? IndexPage : LoginPage);
        }

        private static bool IsValidRegistrationRequest(RegistrationRequest request)
        {
            return ValidationHelpers.IsValidInput(request.Username, "-_.")
                && ValidationHelpers.IsValidInput(request.Email, "@._+-")
                && ValidationHelpers.IsValidXSSInput(request.Username)
                && ValidationHelpers.IsValidXSSInput(request.Email);
        }

        private static bool IsValidLoginRequest(LoginRequest request)
        {
            return ValidationHelpers.IsValidInput(request.Username, "-_.")
                && ValidationHelpers.IsValidXSSInput(request.Username);
        }
    }

    public class RegistrationRequest
    {
        public required string Username { get; set; }
        public required string Email { get; set; }
        public required string Password { get; set; }
    }

    public class LoginRequest
    {
        public required string Username { get; set; }
        public required string Password { get; set; }
    }
}
