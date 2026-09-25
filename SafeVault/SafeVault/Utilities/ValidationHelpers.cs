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
}
