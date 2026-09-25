"use strict";

SafeVaultAuth.redirectAuthenticatedUser();
SafeVaultAuth.bindForm("register-form", "/api/auth/register", ["username", "email", "password"]);
