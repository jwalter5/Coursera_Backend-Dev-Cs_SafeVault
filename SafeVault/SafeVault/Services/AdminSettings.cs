namespace SafeVault.Services;

public sealed class AdminSettings
{
    public const string SectionName = "Admin";

    public required string Username { get; init; }
    public required string Email { get; init; }
    public required string Password { get; init; }
}
