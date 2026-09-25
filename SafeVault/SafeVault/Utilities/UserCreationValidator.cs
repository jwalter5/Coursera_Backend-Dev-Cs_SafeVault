using SafeVault.Models;

namespace SafeVault.Utilities;

public static class UserCreationValidator
{
    public static bool IsValid(string? username, string? email, string? password)
    {
        return !string.IsNullOrWhiteSpace(username)
            && !string.IsNullOrWhiteSpace(email)
            && !string.IsNullOrWhiteSpace(password)
            && username.Length <= UserInputLimits.UsernameMaxLength
            && email.Length <= UserInputLimits.EmailMaxLength
            && password.Length <= UserInputLimits.PasswordMaxLength
            && ValidationHelpers.IsValidInput(username, "-_.")
            && ValidationHelpers.IsValidInput(email, "@._+-")
            && ValidationHelpers.IsValidEmail(email)
            && ValidationHelpers.IsValidXSSInput(username)
            && ValidationHelpers.IsValidXSSInput(email);
    }
}
