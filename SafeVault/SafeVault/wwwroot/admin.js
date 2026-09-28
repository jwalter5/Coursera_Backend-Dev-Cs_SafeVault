(() => {
    "use strict";

    const page = document.getElementById("admin-page");
    const usersBody = document.getElementById("users");
    const statusMessage = document.getElementById("status-message");
    const passwordDialog = document.getElementById("confirm-password-dialog");
    const passwordForm = document.getElementById("confirm-password-form");
    const passwordPrompt = document.getElementById("confirm-password-prompt");
    const cancelPasswordButton = document.getElementById("cancel-password-confirmation");
    let resolvePasswordConfirmation;

    function finishPasswordConfirmation(password) {
        if (!resolvePasswordConfirmation) {
            return;
        }

        const resolve = resolvePasswordConfirmation;
        resolvePasswordConfirmation = null;
        passwordDialog.close();
        resolve(password);
    }

    function requestCurrentPassword(message) {
        passwordForm.reset();
        passwordPrompt.textContent = message;
        passwordDialog.showModal();
        document.getElementById("admin-current-password").focus();

        return new Promise(resolve => {
            resolvePasswordConfirmation = resolve;
        });
    }

    passwordForm.addEventListener("submit", event => {
        event.preventDefault();
        const formData = new FormData(passwordForm);
        finishPasswordConfirmation(formData.get("currentPassword"));
    });
    cancelPasswordButton.addEventListener("click", () => finishPasswordConfirmation(null));
    passwordDialog.addEventListener("cancel", event => {
        event.preventDefault();
        finishPasswordConfirmation(null);
    });

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
        label.textContent = `Role for ${user.username}`;

        const select = document.createElement("select");
        select.id = `role-${user.userId}`;
        select.setAttribute("aria-label", `Role for ${user.username}`);
        for (const role of ["User", "Admin"]) {
            const option = document.createElement("option");
            option.value = role;
            option.textContent = role;
            option.selected = role === user.role;
            select.append(option);
        }

        const saveButton = document.createElement("button");
        saveButton.type = "button";
        saveButton.textContent = "Save";
        saveButton.addEventListener("click", async () => {
            const currentPassword = await requestCurrentPassword(
                `Confirm the role change for ${user.username} with your password.`);
            if (currentPassword === null) {
                select.value = user.role;
                return;
            }

            saveButton.disabled = true;
            statusMessage.classList.remove("error");
            statusMessage.textContent = `Saving the role for ${user.username} …`;

            try {
                const response = await SafeVaultAuth.fetchWithAuth("/api/users/role", {
                    method: "PUT",
                    headers: {
                        "Content-Type": "application/json"
                    },
                    body: JSON.stringify({
                        userId: user.userId,
                        role: select.value,
                        currentPassword
                    })
                });

                if (!response || response.status === 401 || response.status === 403) {
                    window.location.replace("/");
                    return;
                }

                if (!response.ok) {
                    const result = await response.json().catch(() => ({}));
                    showError(result.message ?? "The role could not be saved.");
                    return;
                }

                user.role = select.value;
                statusMessage.textContent = `The role for ${user.username} has been saved.`;
            } catch {
                showError("SafeVault is currently unavailable.");
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
        deleteButton.textContent = "Delete";
        deleteButton.setAttribute("aria-label", `Delete ${user.username}`);

        deleteButton.addEventListener("click", async () => {
            if (!window.confirm(`Are you sure you want to permanently delete ${user.username}?`)) {
                return;
            }

            const currentPassword = await requestCurrentPassword(
                `Confirm the deletion of ${user.username} with your password.`);
            if (currentPassword === null) {
                return;
            }

            deleteButton.disabled = true;
            statusMessage.classList.remove("error");
            statusMessage.textContent = `Deleting ${user.username} …`;

            try {
                const response = await SafeVaultAuth.fetchWithAuth("/api/users", {
                    method: "DELETE",
                    headers: {
                        "Content-Type": "application/json",
                        id: user.userId
                    },
                    body: JSON.stringify({ currentPassword })
                });

                if (!response || response.status === 401 || response.status === 403) {
                    window.location.replace("/");
                    return;
                }

                if (!response.ok) {
                    const result = await response.json().catch(() => ({}));
                    showError(result.message ?? `${user.username} could not be deleted.`);
                    return;
                }

                if (user.userId === currentUserId) {
                    SafeVaultAuth.logout();
                    return;
                }

                row.remove();
                statusMessage.textContent = `${user.username} has been deleted.`;
            } catch {
                showError("SafeVault is currently unavailable.");
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
                showError("The user list could not be loaded.");
                page.hidden = false;
                return;
            }

            renderUsers(await response.json(), currentUser.userId);
            page.hidden = false;
        } catch {
            showError("SafeVault is currently unavailable.");
            page.hidden = false;
        }
    }

    initialize();
})();
