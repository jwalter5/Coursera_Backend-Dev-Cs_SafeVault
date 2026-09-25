using System.IdentityModel.Tokens.Jwt;
using Microsoft.Extensions.Options;
using NUnit.Framework;
using SafeVault.Models;
using SafeVault.Services;

[TestFixture]
public class JwtTokenServiceTests
{
    [Test]
    public void CreatedTokenContainsUserIdAndRoleAndExpiresInThirtyMinutes()
    {
        var settings = new JwtSettings
        {
            Key = "a-test-signing-key-that-is-at-least-thirty-two-bytes-long",
            Issuer = "SafeVault.Tests",
            Audience = "SafeVault.Tests",
            ExpirationMinutes = 30
        };
        var service = new JwtTokenService(Options.Create(settings));
        var user = new User
        {
            UserID = 42,
            Username = "test-user",
            Email = "test@example.com",
            Password = "not-used",
            Role = "Admin"
        };
        var beforeCreation = DateTime.UtcNow;

        var result = service.CreateToken(user);
        var token = new JwtSecurityTokenHandler().ReadJwtToken(result.Token);

        Assert.Multiple(() =>
        {
            Assert.That(token.Subject, Is.EqualTo("42"));
            Assert.That(token.Claims.Single(claim => claim.Type == "role").Value, Is.EqualTo("Admin"));
            Assert.That(result.ExpiresAt, Is.InRange(
                beforeCreation.AddMinutes(30),
                DateTime.UtcNow.AddMinutes(30)));
        });
    }
}
