"use strict";

SafeVaultAuth.showCurrentUser();
SafeVaultAuth.bindChangePasswordDialog();
SafeVaultAuth.bindDeleteAccountDialog();
document.getElementById("logout").addEventListener("click", SafeVaultAuth.logout);
