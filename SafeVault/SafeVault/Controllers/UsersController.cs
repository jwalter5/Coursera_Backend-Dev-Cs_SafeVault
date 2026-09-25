using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SafeVault.Data;
using SafeVault.Utilities;

namespace SafeVault.Controllers;

[ApiController]
[Authorize(Roles = "Admin")]
[Route("api/users")]
public sealed class UsersController : ControllerBase
{
    private readonly UserRepository _userRepository;

    public UsersController(UserRepository userRepository)
    {
        _userRepository = userRepository;
    }

    [HttpGet]
    public ActionResult<IReadOnlyList<UserResponse>> GetAll()
    {
        return Ok(_userRepository.GetAll().Select(UserResponse.FromUser));
    }

    [HttpGet("{userId:int}")]
    public ActionResult<UserResponse> GetById(int userId)
    {
        var user = _userRepository.GetById(userId);
        return user is null ? NotFound() : Ok(UserResponse.FromUser(user));
    }

    [HttpDelete("{userId:int}")]
    public IActionResult Delete(int userId)
    {
        return _userRepository.Delete(userId) ? NoContent() : NotFound();
    }

    [HttpPut("{userId:int}")]
    public ActionResult<UserResponse> Update(int userId, [FromBody] UpdateUserRequest request)
    {
        if (!ValidationHelpers.IsValidInput(request.Username, "-_.")
            || !ValidationHelpers.IsValidInput(request.Email, "@._+-")
            || !ValidationHelpers.IsValidXSSInput(request.Username)
            || !ValidationHelpers.IsValidXSSInput(request.Email)
            || (request.Role != "User" && request.Role != "Admin"))
        {
            return BadRequest(new { message = "The user information is invalid." });
        }

        var user = _userRepository.GetById(userId);
        if (user is null)
        {
            return NotFound();
        }

        user.Username = request.Username;
        user.Email = request.Email;
        user.Role = request.Role;
        _userRepository.Update(user);

        return Ok(UserResponse.FromUser(user));
    }
}

public sealed record UpdateUserRequest(string Username, string Email, string Role);
