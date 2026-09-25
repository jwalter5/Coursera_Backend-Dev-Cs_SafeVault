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

    public UsersController(UserRepository userRepository) =>
        _userRepository = userRepository;

    [Authorize(Roles = "Admin")]
    [HttpGet("all")]
    public ActionResult<IReadOnlyList<UserResponse>> GetAll() =>
        Ok(_userRepository.GetAll().Select(UserResponse.FromUser));

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
    public IActionResult Delete([FromHeader(Name = "id")] int? requestedUserId)
    {
        var userIdResult = ResolveUserId(requestedUserId);
        if (userIdResult.Result is not null)
            return userIdResult.Result;

        if (!_userRepository.Delete(userIdResult.Value))
            return NotFound();

        if (int.TryParse(User.FindFirstValue(JwtRegisteredClaimNames.Sub), out var currentUserId)
            && currentUserId == userIdResult.Value)
        {
            AuthenticationCookie.Delete(Response);
        }

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

        var user = _userRepository.GetById(request.UserId);
        if (user is null)
            return NotFound();

        user.Role = request.Role;
        _userRepository.UpdateRole(request.UserId, request.Role);

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

        return NoContent();
    }

    private ActionResult<int> ResolveUserId(int? requestedUserId)
    {
        if (!int.TryParse(User.FindFirstValue(JwtRegisteredClaimNames.Sub), out var currentUserId))
            return Unauthorized();

        if (requestedUserId is null || requestedUserId == currentUserId)
            return currentUserId;

        return User.IsInRole("Admin") ? requestedUserId.Value : Forbid();
    }
}

public sealed record UpdateUserRoleRequest(int UserId, string Role);
public sealed record ChangePasswordRequest(string OldPassword, string NewPassword);
