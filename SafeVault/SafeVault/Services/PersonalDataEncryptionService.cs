using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace SafeVault.Services;

public sealed class PersonalDataEncryptionService
{
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const string FormatVersion = "v1";
    private readonly byte[] _key;

    public PersonalDataEncryptionService(IOptions<AesSettings> settings)
    {
        try
        {
            _key = Convert.FromBase64String(settings.Value.Key);
        }
        catch (FormatException exception)
        {
            throw new InvalidOperationException("The AES key must be Base64 encoded.", exception);
        }

        if (_key.Length != 32)
            throw new InvalidOperationException("The AES key must decode to exactly 32 bytes.");
    }

    public string Encrypt(string plaintext, int userId)
    {
        var nonce = RandomNumberGenerator.GetBytes(NonceSize);
        var plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        var ciphertext = new byte[plaintextBytes.Length];
        var tag = new byte[TagSize];

        using var aes = new AesGcm(_key, TagSize);
        aes.Encrypt(nonce, plaintextBytes, ciphertext, tag, GetAssociatedData(userId));

        return string.Join('.',
            FormatVersion,
            Convert.ToBase64String(nonce),
            Convert.ToBase64String(tag),
            Convert.ToBase64String(ciphertext));
    }

    public string Decrypt(string encryptedValue, int userId)
    {
        var parts = encryptedValue.Split('.', 4);
        if (parts.Length != 4 || parts[0] != FormatVersion)
            throw new CryptographicException("The encrypted personal data has an invalid format.");

        try
        {
            var nonce = Convert.FromBase64String(parts[1]);
            var tag = Convert.FromBase64String(parts[2]);
            var ciphertext = Convert.FromBase64String(parts[3]);
            if (nonce.Length != NonceSize || tag.Length != TagSize)
                throw new CryptographicException("The encrypted personal data has an invalid format.");

            var plaintext = new byte[ciphertext.Length];
            using var aes = new AesGcm(_key, TagSize);
            aes.Decrypt(nonce, ciphertext, tag, plaintext, GetAssociatedData(userId));
            return Encoding.UTF8.GetString(plaintext);
        }
        catch (FormatException exception)
        {
            throw new CryptographicException("The encrypted personal data has an invalid format.", exception);
        }
    }

    private static byte[] GetAssociatedData(int userId) =>
        Encoding.UTF8.GetBytes($"SafeVault.PersonalData:{userId}");
}
