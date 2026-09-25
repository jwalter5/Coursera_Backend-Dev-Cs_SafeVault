namespace SafeVault.Services;

public static class AuthenticationCookie
{
    public const string Name = "__Host-SafeVaultAuth";

    public static void Append(HttpResponse response, TokenResult token)
    {
        response.Cookies.Append(Name, token.Token, CreateOptions(token.ExpiresAt));
    }

    public static void Delete(HttpResponse response)
    {
        response.Cookies.Delete(Name, CreateOptions());
    }

    private static CookieOptions CreateOptions(DateTime? expiresAt = null)
    {
        return new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.Strict,
            Path = "/",
            IsEssential = true,
            Expires = expiresAt
        };
    }
}
