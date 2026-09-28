namespace SafeVault.Services;

public sealed class AesSettings
{
    public const string SectionName = "Aes";

    public required string Key { get; init; }
}
