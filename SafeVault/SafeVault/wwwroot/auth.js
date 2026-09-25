window.SafeVaultAuth = (() => {
    "use strict";

    let antiforgeryToken;

    async function getAntiforgeryToken() {
        if (antiforgeryToken) {
            return antiforgeryToken;
        }

        const response = await fetch("/api/auth/antiforgery-token", {
            credentials: "same-origin",
            cache: "no-store"
        });
        if (!response.ok) {
            throw new Error("Could not obtain an antiforgery token.");
        }

        const result = await response.json();
        antiforgeryToken = result.token;
        return antiforgeryToken;
    }

    async function getCurrentUser() {
        const response = await fetch("/api/users", {
            credentials: "same-origin"
        });

        if (!response.ok) {
            return null;
        }

        return response.json();
    }

    async function fetchWithAuth(url, options = {}) {
        const headers = new Headers(options.headers);
        const method = (options.method ?? "GET").toUpperCase();
        if (!["GET", "HEAD", "OPTIONS", "TRACE"].includes(method)) {
            headers.set("X-CSRF-TOKEN", await getAntiforgeryToken());
        }

        return fetch(url, {
            ...options,
            credentials: "same-origin",
            headers
        });
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
            if (user.role === "Admin") {
                document.getElementById("admin-actions").hidden = false;
            }
            userView.hidden = false;
        } catch {
            guestView.hidden = false;
        }
    }

    async function redirectAuthenticatedUser() {
        try {
            if (await getCurrentUser()) {
                window.location.replace("/");
            }
        } catch { }
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
                const response = await fetchWithAuth(endpoint, {
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

                window.location.assign("/");
            } catch {
                errorMessage.textContent = "SafeVault ist momentan nicht erreichbar.";
                errorMessage.hidden = false;
            }
        });
    }

    async function logout() {
        try {
            await fetchWithAuth("/api/auth/logout", { method: "POST" });
        } finally {
            window.location.reload();
        }
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
                    await logout();
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
                await logout();
                return;
            }

            if (!response.ok) {
                statusMessage.classList.add("error");
                statusMessage.textContent = "Das Konto konnte nicht gelöscht werden.";
                return;
            }

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
        logout,
        redirectAuthenticatedUser,
        showCurrentUser
    };
})();
