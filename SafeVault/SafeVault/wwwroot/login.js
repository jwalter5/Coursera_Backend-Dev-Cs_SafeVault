"use strict";

SafeVaultAuth.redirectAuthenticatedUser();
SafeVaultAuth.bindForm("login-form", "/api/auth/login", ["username", "password"]);
