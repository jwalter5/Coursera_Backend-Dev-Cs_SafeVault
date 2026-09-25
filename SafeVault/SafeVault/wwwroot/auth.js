window.SafeVaultAuth = (() => {
    "use strict";

    const tokenKey = "safeVaultToken";

    function getToken() {
        return localStorage.getItem(tokenKey);
    }

    function saveToken(token) {
        localStorage.setItem(tokenKey, token);
    }

    function clearToken() {
        localStorage.removeItem(tokenKey);
    }

    function hasRole(role) {
        const token = getToken();
        if (!token) {
            return false;
        }

        try {
            const encodedPayload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
            const payload = JSON.parse(atob(encodedPayload));
            return payload.role === role;
        } catch {
            return false;
        }
    }

    async function getCurrentUser() {
        const token = getToken();
        if (!token) {
            return null;
        }

        const response = await fetch("/api/users", {
            headers: { Authorization: `Bearer ${token}` }
        });

        if (!response.ok) {
            clearToken();
            return null;
        }

        return response.json();
    }

    async function fetchWithAuth(url, options = {}) {
        const token = getToken();
        if (!token) {
            return null;
        }

        const headers = new Headers(options.headers);
        headers.set("Authorization", `Bearer ${token}`);
        return fetch(url, { ...options, headers });
    }

    async function showCurrentUser() {
        const guestView = document.getElementById("guest-view");
        const userView = document.getElementById("user-view");

        try {
            const user = await getCurrentUser();
            if (!user) {
                guestView.hidden = false;
                return;
            }

            document.getElementById("username").textContent = user.username;
            document.getElementById("email").textContent = user.email;
            document.getElementById("role").textContent = user.role;
            if (hasRole("Admin")) {
                document.getElementById("admin-actions").hidden = false;
            }
            userView.hidden = false;
        } catch {
            clearToken();
            guestView.hidden = false;
        }
    }

    async function redirectAuthenticatedUser() {
        try {
            if (await getCurrentUser()) {
                window.location.replace("/");
            }
        } catch {
            clearToken();
        }
    }

    function bindForm(formId, endpoint, fieldNames) {
        const form = document.getElementById(formId);
        const errorMessage = document.getElementById("error-message");

        form.addEventListener("submit", async event => {
            event.preventDefault();
            errorMessage.hidden = true;

            const formData = new FormData(form);
            const body = Object.fromEntries(fieldNames.map(name => [name, formData.get(name)]));

            try {
                const response = await fetch(endpoint, {
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify(body)
                });
                const result = await response.json();

                if (!response.ok) {
                    errorMessage.textContent = result.message ?? "Die Anfrage konnte nicht verarbeitet werden.";
                    errorMessage.hidden = false;
                    return;
                }

                saveToken(result.token);
                window.location.assign("/");
            } catch {
                errorMessage.textContent = "SafeVault ist momentan nicht erreichbar.";
                errorMessage.hidden = false;
            }
        });
    }

    function logout() {
        clearToken();
        window.location.reload();
    }

    function bindChangePasswordDialog() {
        const dialog = document.getElementById("change-password-dialog");
        const form = document.getElementById("change-password-form");
        const openButton = document.getElementById("open-change-password");
        const cancelButton = document.getElementById("cancel-change-password");
        const errorMessage = document.getElementById("change-password-error");

        openButton.addEventListener("click", () => {
            form.reset();
            errorMessage.hidden = true;
            dialog.showModal();
        });

        cancelButton.addEventListener("click", () => dialog.close());

        form.addEventListener("submit", async event => {
            event.preventDefault();
            errorMessage.hidden = true;

            const formData = new FormData(form);
            const newPassword = formData.get("newPassword");
            if (newPassword !== formData.get("confirmNewPassword")) {
                errorMessage.textContent = "Die neuen Passwörter stimmen nicht überein.";
                errorMessage.hidden = false;
                return;
            }

            const submitButton = form.querySelector('button[type="submit"]');
            submitButton.disabled = true;

            try {
                const response = await fetchWithAuth("/api/users/changePassword", {
                    method: "PUT",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({
                        oldPassword: formData.get("oldPassword"),
                        newPassword
                    })
                });

                if (!response || response.status === 401) {
                    clearToken();
                    window.location.reload();
                    return;
                }

                if (!response.ok) {
                    const result = await response.json().catch(() => ({}));
                    errorMessage.textContent = result.message ?? "Das Passwort konnte nicht geändert werden.";
                    errorMessage.hidden = false;
                    return;
                }

                dialog.close();
                form.reset();
                const statusMessage = document.getElementById("account-status");
                statusMessage.classList.remove("error");
                statusMessage.textContent = "Das Passwort wurde geändert.";
            } catch {
                errorMessage.textContent = "SafeVault ist momentan nicht erreichbar.";
                errorMessage.hidden = false;
            } finally {
                submitButton.disabled = false;
            }
        });
    }

    async function deleteCurrentUser() {
        if (!window.confirm("Möchtest du dein Konto wirklich unwiderruflich löschen?")) {
            return;
        }

        const deleteButton = document.getElementById("delete-account");
        const statusMessage = document.getElementById("account-status");
        deleteButton.disabled = true;
        statusMessage.classList.remove("error");
        statusMessage.textContent = "Konto wird gelöscht …";

        try {
            const response = await fetchWithAuth("/api/users", { method: "DELETE" });
            if (!response || response.status === 401) {
                clearToken();
                window.location.reload();
                return;
            }

            if (!response.ok) {
                statusMessage.classList.add("error");
                statusMessage.textContent = "Das Konto konnte nicht gelöscht werden.";
                return;
            }

            clearToken();
            window.location.reload();
        } catch {
            statusMessage.classList.add("error");
            statusMessage.textContent = "SafeVault ist momentan nicht erreichbar.";
        } finally {
            deleteButton.disabled = false;
        }
    }

    return {
        bindForm,
        bindChangePasswordDialog,
        deleteCurrentUser,
        fetchWithAuth,
        getCurrentUser,
        hasRole,
        logout,
        redirectAuthenticatedUser,
        showCurrentUser
    };
})();
