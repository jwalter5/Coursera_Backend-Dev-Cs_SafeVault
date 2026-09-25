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

    async function getCurrentUser() {
        const token = getToken();
        if (!token) {
            return null;
        }

        const response = await fetch("/api/auth/me", {
            headers: { Authorization: `Bearer ${token}` }
        });

        if (!response.ok) {
            clearToken();
            return null;
        }

        return response.json();
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

    return { bindForm, logout, redirectAuthenticatedUser, showCurrentUser };
})();
