using System.Net.Mail;

namespace SafeVault.Utilities;

public static class ValidationHelpers
{
    public static bool IsValidInput(string input, string allowedSpecialCharacters = "")
    {
        if (string.IsNullOrEmpty(input))
            return true;

        return input.All(character =>
            char.IsLetterOrDigit(character) || allowedSpecialCharacters.Contains(character));
    }

    public static bool IsValidXSSInput(string input)
    {
        if (input is null)
            return true;

        return !input.Contains("<script", StringComparison.OrdinalIgnoreCase)
            && !input.Contains("<iframe", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsValidEmail(string input)
    {
        if (string.IsNullOrWhiteSpace(input)
            || !MailAddress.TryCreate(input, out var emailAddress)
            || !string.Equals(emailAddress.Address, input, StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        var domain = input[(input.LastIndexOf('@') + 1)..];
        return domain.Contains('.')
            && !domain.StartsWith('.')
            && !domain.EndsWith('.');
    }
}
