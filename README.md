# Coursera_Backend-Dev-Cs_SafeVault
Repository for the final project of the coursera course "Microsoft Back-End Developer Professional Certificate - Security and Authentication"

## Authentication

Registration and login use `POST /api/auth/register` and `POST /api/auth/login`. Both
return a JWT bearer token containing the user ID and role. Tokens expire after 30 minutes.
The browser stores the token in `localStorage`; the logout button removes it.

Authenticated users can get or delete their own account through `/api/users`; the user ID is read
from the token's `sub` claim. Administrators can target another account for those operations by
supplying its ID in the `id` request header. `GET /api/users/all` and role changes require the
`Admin` role. Role changes use `PUT /api/users/role` with the target `userId` and new `role` in the
request body. Usernames and email addresses cannot be changed.

Logged-in administrators can open `/admin.html` from the homepage to view all users and
change their roles. Role-based permissions follow the JWT and therefore change after the affected
user logs in again.

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
  "Admin": {
    "Username": "admin",
    "Email": "admin@example.com",
    "Password": "replace-this-with-a-strong-admin-password"
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
- `Admin:Username`, `Admin:Email`, and `Admin:Password` define the standard administrator
  account that is created when the application starts. The password is hashed before it is
  stored in the database. Replace all example credentials, especially the password, with values
  suitable for your environment.

For deployments, supply secrets through the hosting environment instead of a settings file.
ASP.NET Core configuration uses double underscores for nested environment variables, so the
signing key can be provided as `Jwt__Key`. The other settings can likewise be overridden with
`Jwt__Issuer`, `Jwt__Audience`, and `Jwt__ExpirationMinutes`. Administrator settings can be
provided as `Admin__Username`, `Admin__Email`, and `Admin__Password`.
