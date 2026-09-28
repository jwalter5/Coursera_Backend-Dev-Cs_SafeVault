using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Data;
using SafeVault.Models;
using SafeVault.Services;

namespace SafeVault.Controllers;

[ApiController]
[Authorize]
[Route("api/users")]
public sealed class UsersController : ControllerBase
{
    private readonly UserRepository _userRepository;
    private readonly JwtTokenService _jwtTokenService;

    public UsersController(UserRepository userRepository, JwtTokenService jwtTokenService)
    {
        _userRepository = userRepository;
        _jwtTokenService = jwtTokenService;
    }

    [Authorize(Roles = "Admin")]
    [HttpGet("all")]
    public ActionResult<IReadOnlyList<AdminUserResponse>> GetAll() =>
        Ok(_userRepository.GetAll().Select(AdminUserResponse.FromUser));

    [HttpGet]
    public ActionResult<UserResponse> GetById([FromHeader(Name = "id")] int? requestedUserId)
    {
        var userIdResult = ResolveUserId(requestedUserId);
        if (userIdResult.Result is not null)
            return userIdResult.Result;

        var user = _userRepository.GetById(userIdResult.Value);
        return user is null ? NotFound() : Ok(UserResponse.FromUser(user));
    }

    [HttpDelete]
    public IActionResult Delete(
        [FromHeader(Name = "id")] int? requestedUserId,
        [FromBody] DeleteUserRequest request)
    {
        var userIdResult = ResolveUserId(requestedUserId);
        if (userIdResult.Result is not null)
            return userIdResult.Result;

        if (!TryGetCurrentUserId(out var currentUserId))
            return Unauthorized();

        var currentUser = _userRepository.GetById(currentUserId);
        if (currentUser is null)
            return Unauthorized();

        if (userIdResult.Value != currentUserId && currentUser.Role != "Admin")
            return Forbid();

        if (!IsValidPasswordConfirmation(request.CurrentPassword)
            || !_userRepository.VerifyPassword(currentUserId, request.CurrentPassword))
        {
            return BadRequest(new { message = "The current password is incorrect." });
        }

        var deleteResult = _userRepository.Delete(userIdResult.Value);
        if (deleteResult == UserMutationResult.NotFound)
            return NotFound();

        if (deleteResult == UserMutationResult.LastAdministrator)
            return Conflict(new { message = "The final administrator cannot be deleted." });

        if (currentUserId == userIdResult.Value)
            AuthenticationCookie.Delete(Response);

        return NoContent();
    }

    [Authorize(Roles = "Admin")]
    [HttpPut("role")]
    public ActionResult<UserResponse> UpdateRole(
        [FromBody] UpdateUserRoleRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Role)
            || request.Role.Length > UserInputLimits.RoleMaxLength
            || (request.Role != "User" && request.Role != "Admin"))
            return BadRequest(new { message = "The role must be either User or Admin." });

        if (!TryGetCurrentUserId(out var currentUserId))
            return Unauthorized();

        var currentUser = _userRepository.GetById(currentUserId);
        if (currentUser is null)
            return Unauthorized();

        if (currentUser.Role != "Admin")
            return Forbid();

        if (!IsValidPasswordConfirmation(request.CurrentPassword)
            || !_userRepository.VerifyPassword(currentUserId, request.CurrentPassword))
        {
            return BadRequest(new { message = "The current password is incorrect." });
        }

        var updateResult = _userRepository.UpdateRole(request.UserId, request.Role);
        if (updateResult == UserMutationResult.NotFound)
            return NotFound();

        if (updateResult == UserMutationResult.LastAdministrator)
            return Conflict(new { message = "The final administrator cannot be demoted." });

        var user = _userRepository.GetById(request.UserId)!;
        if (currentUserId == request.UserId)
            AuthenticationCookie.Append(Response, _jwtTokenService.CreateToken(user));

        return Ok(UserResponse.FromUser(user));
    }

    [HttpPut("changePassword")]
    public IActionResult ChangePassword([FromBody] ChangePasswordRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.OldPassword)
            || string.IsNullOrWhiteSpace(request.NewPassword)
            || request.OldPassword.Length > UserInputLimits.PasswordMaxLength
            || request.NewPassword.Length > UserInputLimits.PasswordMaxLength)
        {
            return BadRequest(new
            {
                message = $"The old and new passwords are required and must not exceed {UserInputLimits.PasswordMaxLength} characters."
            });
        }

        var userIdResult = ResolveUserId(null);
        if (userIdResult.Result is not null)
            return userIdResult.Result;

        if (!_userRepository.ChangePassword(userIdResult.Value, request.OldPassword, request.NewPassword))
            return BadRequest(new { message = "The old password is incorrect." });

        var user = _userRepository.GetById(userIdResult.Value);
        if (user is null)
            return Unauthorized();

        AuthenticationCookie.Append(Response, _jwtTokenService.CreateToken(user));
        return NoContent();
    }

    [HttpGet("personal-data")]
    public ActionResult<PersonalDataResponse> GetPersonalData()
    {
        if (!TryGetCurrentUserId(out var currentUserId))
            return Unauthorized();

        if (_userRepository.GetById(currentUserId) is null)
            return Unauthorized();

        return Ok(new PersonalDataResponse(
            _userRepository.GetPersonalData(currentUserId) ?? string.Empty));
    }

    [HttpPut("personal-data")]
    public IActionResult SavePersonalData([FromBody] SavePersonalDataRequest request)
    {
        if (request.PersonalData is null
            || request.PersonalData.Length > UserInputLimits.PersonalDataMaxLength)
        {
            return BadRequest(new
            {
                message = $"Personal data must not exceed {UserInputLimits.PersonalDataMaxLength} characters."
            });
        }

        if (!TryGetCurrentUserId(out var currentUserId))
            return Unauthorized();

        return _userRepository.SavePersonalData(currentUserId, request.PersonalData)
            ? NoContent()
            : Unauthorized();
    }

    private ActionResult<int> ResolveUserId(int? requestedUserId)
    {
        if (!TryGetCurrentUserId(out var currentUserId))
            return Unauthorized();

        if (requestedUserId is null || requestedUserId == currentUserId)
            return currentUserId;

        return User.IsInRole("Admin") ? requestedUserId.Value : Forbid();
    }

    private bool TryGetCurrentUserId(out int currentUserId) =>
        int.TryParse(User.FindFirstValue(JwtRegisteredClaimNames.Sub), out currentUserId);

    private static bool IsValidPasswordConfirmation(string password) =>
        !string.IsNullOrWhiteSpace(password)
        && password.Length <= UserInputLimits.PasswordMaxLength;
}

public sealed record DeleteUserRequest(string CurrentPassword);
public sealed record UpdateUserRoleRequest(int UserId, string Role, string CurrentPassword);
public sealed record ChangePasswordRequest(string OldPassword, string NewPassword);
public sealed record SavePersonalDataRequest(string PersonalData);
public sealed record PersonalDataResponse(string PersonalData);
public sealed record AdminUserResponse(int UserId, string Username, string Email, string Role)
{
    public static AdminUserResponse FromUser(User user) =>
        new(user.UserID, user.Username, MaskEmail(user.Email), user.Role);

    private static string MaskEmail(string email)
    {
        var atIndex = email.IndexOf('@');
        var lastDotIndex = email.LastIndexOf('.');

        if (atIndex <= 0 || lastDotIndex <= atIndex + 1)
            return email;

        var localPart = email[..atIndex];
        var domain = email[(atIndex + 1)..lastDotIndex];
        var topLevelDomain = email[lastDotIndex..];

        return $"{localPart[0]}{new string('*', localPart.Length - 1)}"
            + $"@{domain[0]}{new string('*', domain.Length - 1)}{topLevelDomain}";
    }
}
