# Coursera_Backend-Dev-Cs_SafeVault
Repository for the final project of the coursera course "Microsoft Back-End Developer Professional Certificate - Security and Authentication"

A simple web application developed with the use of AI.
Functionalities:
 - Registration of new users
 - Login/Logout with existing users
 - Change Password or delete account for user-role authorization
 - View and edit per-user personal data encrypted at rest with AES-256-GCM
 - Manage other users with the admin-role (view all users, change role, delete account)

For simplicity, an in-memory database is used.

## Authentication

Registration and login use `POST /api/auth/register` and `POST /api/auth/login`. Both issue a JWT
containing the user ID and role in a Secure, HttpOnly, SameSite cookie. Tokens expire after 30
minutes. The browser cannot read the token, and the logout endpoint expires its cookie.

Authenticated users can get or delete their own account through `/api/users`; the user ID is read
from the token's `sub` claim. Administrators can target another account for those operations by
supplying its ID in the `id` request header. `GET /api/users/all` and role changes require the
`Admin` role. Role changes use `PUT /api/users/role` with the target `userId`, new `role`, and the
acting administrator's `currentPassword` in the request body. Account deletion likewise requires
`{ "currentPassword": "..." }` in the request body. The final administrator cannot be deleted or
demoted. Usernames and email addresses cannot be changed.

Changing a password replaces the browser's authentication cookie with a newly issued JWT. Because 
JWT validation remains stateless, tokens copied before a password change remain valid until their 
normal expiration; immediate revocation would require a server-side token version or revocation store.

Logged-in administrators can open `/admin.html` from the homepage to view all users and
change their roles. Role-based permissions follow the JWT and therefore change after the affected
user logs in again.

Personal data is read and saved through `GET` and `PUT /api/users/personal-data`. These routes
always derive the record ID from the authenticated token and do not accept a target user ID.
Consequently, administrators can manage only their own personal data and cannot retrieve another
user's personal data. The value is encrypted before it is written to the database.

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
  "Aes": {
    "Key": "replace-with-a-base64-encoded-random-32-byte-key"
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
- `Aes:Key` is a Base64-encoded, random 32-byte key used for AES-256-GCM encryption of each
  user's personal data. Keep it secret and stable: changing or losing it makes existing personal
  data unreadable. Generate one with `openssl rand -base64 32`.

For deployments, supply secrets through the hosting environment instead of a settings file.
ASP.NET Core configuration uses double underscores for nested environment variables, so the
signing key can be provided as `Jwt__Key`. The other settings can likewise be overridden with
`Jwt__Issuer`, `Jwt__Audience`, and `Jwt__ExpirationMinutes`. Administrator settings can be
provided as `Admin__Username`, `Admin__Email`, and `Admin__Password`.
The AES key can be provided as `Aes__Key`.
