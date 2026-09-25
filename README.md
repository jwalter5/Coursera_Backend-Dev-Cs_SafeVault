# Coursera_Backend-Dev-Cs_SafeVault
Repository for the final project of the coursera course "Microsoft Back-End Developer Professional Certificate - Security and Authentication"

## Authentication

Registration and login use `POST /api/auth/register` and `POST /api/auth/login`. Both
return a JWT bearer token containing the user ID and role. Tokens expire after 30 minutes.
The browser stores the token in `localStorage`; the logout button removes it.

`GET /api/auth/me` requires a bearer token. User listing, lookup, update, and deletion under
`/api/users` require the `Admin` role.

## Local configuration

The application requires JWT settings at startup. Because `appsettings.json` is intentionally
excluded from Git, create `SafeVault/SafeVault/appsettings.json` locally with the following
contents before starting the application:

```json
{
  "Jwt": {
    "Key": "replace-this-with-your-own-secret-key-of-at-least-32-bytes",
    "Issuer": "SafeVault",
    "Audience": "SafeVault.Web",
    "ExpirationMinutes": 30
  },
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft.AspNetCore": "Warning"
    }
  },
  "AllowedHosts": "*"
}
```

- `Key` signs and validates the JWT and must contain at least 32 UTF-8 bytes. Generate your
  own unpredictable value; do not reuse or commit the example value.
- `Issuer` identifies the application that creates the token.
- `Audience` identifies the application for which the token is intended.
- `ExpirationMinutes` must be `30` to keep tokens valid for the required 30-minute period.

For deployments, supply secrets through the hosting environment instead of a settings file.
ASP.NET Core configuration uses double underscores for nested environment variables, so the
signing key can be provided as `Jwt__Key`. The other settings can likewise be overridden with
`Jwt__Issuer`, `Jwt__Audience`, and `Jwt__ExpirationMinutes`.
