(() => {
    "use strict";

    const page = document.getElementById("admin-page");
    const usersBody = document.getElementById("users");
    const statusMessage = document.getElementById("status-message");

    function showError(message) {
        statusMessage.classList.add("error");
        statusMessage.textContent = message;
    }

    function createRoleControls(user) {
        const wrapper = document.createElement("div");
        wrapper.className = "role-controls";

        const label = document.createElement("label");
        label.className = "visually-hidden";
        label.htmlFor = `role-${user.userId}`;
        label.textContent = `Rolle für ${user.username}`;

        const select = document.createElement("select");
        select.id = `role-${user.userId}`;
        select.setAttribute("aria-label", `Rolle für ${user.username}`);
        for (const role of ["User", "Admin"]) {
            const option = document.createElement("option");
            option.value = role;
            option.textContent = role;
            option.selected = role === user.role;
            select.append(option);
        }

        const saveButton = document.createElement("button");
        saveButton.type = "button";
        saveButton.textContent = "Speichern";
        saveButton.addEventListener("click", async () => {
            saveButton.disabled = true;
            statusMessage.classList.remove("error");
            statusMessage.textContent = `Rolle für ${user.username} wird gespeichert …`;

            try {
                const response = await SafeVaultAuth.fetchWithAuth("/api/users/role", {
                    method: "PUT",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({ userId: user.userId, role: select.value })
                });

                if (!response || response.status === 401 || response.status === 403) {
                    window.location.replace("/");
                    return;
                }

                if (!response.ok) {
                    const result = await response.json().catch(() => ({}));
                    showError(result.message ?? "Die Rolle konnte nicht gespeichert werden.");
                    return;
                }

                user.role = select.value;
                statusMessage.textContent = `Rolle für ${user.username} wurde gespeichert.`;
            } catch {
                showError("SafeVault ist momentan nicht erreichbar.");
            } finally {
                saveButton.disabled = false;
            }
        });

        wrapper.append(label, select, saveButton);
        return wrapper;
    }

    function createDeleteButton(user, currentUserId, row) {
        const deleteButton = document.createElement("button");
        deleteButton.type = "button";
        deleteButton.className = "button-danger";
        deleteButton.textContent = "Löschen";
        deleteButton.setAttribute("aria-label", `${user.username} löschen`);

        deleteButton.addEventListener("click", async () => {
            if (!window.confirm(`Möchtest du ${user.username} wirklich unwiderruflich löschen?`)) {
                return;
            }

            deleteButton.disabled = true;
            statusMessage.classList.remove("error");
            statusMessage.textContent = `${user.username} wird gelöscht …`;

            try {
                const response = await SafeVaultAuth.fetchWithAuth("/api/users", {
                    method: "DELETE",
                    headers: { id: user.userId }
                });

                if (!response || response.status === 401 || response.status === 403) {
                    window.location.replace("/");
                    return;
                }

                if (!response.ok) {
                    const result = await response.json().catch(() => ({}));
                    showError(result.message ?? `${user.username} konnte nicht gelöscht werden.`);
                    return;
                }

                if (user.userId === currentUserId) {
                    SafeVaultAuth.logout();
                    return;
                }

                row.remove();
                statusMessage.textContent = `${user.username} wurde gelöscht.`;
            } catch {
                showError("SafeVault ist momentan nicht erreichbar.");
            } finally {
                deleteButton.disabled = false;
            }
        });

        return deleteButton;
    }

    function renderUsers(users, currentUserId) {
        usersBody.replaceChildren();

        for (const user of users) {
            const row = document.createElement("tr");
            for (const value of [user.userId, user.username, user.email]) {
                const cell = document.createElement("td");
                cell.textContent = value;
                row.append(cell);
            }

            const roleCell = document.createElement("td");
            roleCell.append(createRoleControls(user));
            row.append(roleCell);

            const actionsCell = document.createElement("td");
            actionsCell.append(createDeleteButton(user, currentUserId, row));
            row.append(actionsCell);
            usersBody.append(row);
        }
    }

    async function initialize() {
        try {
            const currentUser = await SafeVaultAuth.getCurrentUser();
            if (!currentUser || currentUser.role !== "Admin") {
                window.location.replace("/");
                return;
            }

            const response = await SafeVaultAuth.fetchWithAuth("/api/users/all");
            if (!response || response.status === 401 || response.status === 403) {
                window.location.replace("/");
                return;
            }

            if (!response.ok) {
                showError("Die Benutzerliste konnte nicht geladen werden.");
                page.hidden = false;
                return;
            }

            renderUsers(await response.json(), currentUser.userId);
            page.hidden = false;
        } catch {
            showError("SafeVault ist momentan nicht erreichbar.");
            page.hidden = false;
        }
    }

    initialize();
})();
