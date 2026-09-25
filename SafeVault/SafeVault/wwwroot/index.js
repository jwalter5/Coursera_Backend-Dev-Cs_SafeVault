"use strict";

SafeVaultAuth.showCurrentUser();
SafeVaultAuth.bindChangePasswordDialog();
document.getElementById("logout").addEventListener("click", SafeVaultAuth.logout);
document.getElementById("delete-account").addEventListener("click", SafeVaultAuth.deleteCurrentUser);
