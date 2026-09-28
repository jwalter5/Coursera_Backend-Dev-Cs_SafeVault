"use strict";

SafeVaultAuth.showCurrentUser();
SafeVaultAuth.bindChangePasswordDialog();
SafeVaultAuth.bindDeleteAccountDialog();
document.getElementById("logout").addEventListener("click", SafeVaultAuth.logout);

const personalDataDialog = document.getElementById("personal-data-dialog");
const personalDataUnlockDialog = document.getElementById("personal-data-unlock-dialog");
const personalDataUnlockForm = document.getElementById("unlock-personal-data-form");
const personalDataForm = document.getElementById("personal-data-form");
const personalDataInput = document.getElementById("personal-data");
const personalDataStatus = document.getElementById("personal-data-status");
const personalDataUnlockError = document.getElementById("personal-data-unlock-error");

function clearAndClosePersonalData() {
    personalDataInput.value = "";
    personalDataStatus.textContent = "";
    personalDataStatus.classList.remove("error");
    personalDataDialog.close();
}

function clearAndClosePersonalDataUnlock() {
    personalDataUnlockForm.reset();
    personalDataUnlockError.textContent = "";
    personalDataUnlockError.hidden = true;
    personalDataUnlockDialog.close();
}

document.getElementById("open-personal-data").addEventListener("click", () => {
    personalDataUnlockForm.reset();
    personalDataUnlockError.textContent = "";
    personalDataUnlockError.hidden = true;
    personalDataUnlockDialog.showModal();
});

document.getElementById("cancel-personal-data-unlock")
    .addEventListener("click", clearAndClosePersonalDataUnlock);
document.getElementById("close-personal-data")
    .addEventListener("click", clearAndClosePersonalData);
personalDataUnlockDialog.addEventListener("close", () => {
    personalDataUnlockForm.reset();
    personalDataUnlockError.textContent = "";
    personalDataUnlockError.hidden = true;
});
personalDataDialog.addEventListener("close", () => {
    personalDataInput.value = "";
    personalDataStatus.textContent = "";
    personalDataStatus.classList.remove("error");
});

personalDataUnlockForm.addEventListener("submit", async event => {
    event.preventDefault();
    personalDataUnlockError.hidden = true;
    const submitButton = personalDataUnlockForm.querySelector('button[type="submit"]');
    submitButton.disabled = true;

    try {
        const formData = new FormData(personalDataUnlockForm);
        const response = await SafeVaultAuth.fetchWithAuth("/api/users/personal-data/view", {
            method: "POST",
            cache: "no-store",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ currentPassword: formData.get("currentPassword") })
        });

        if (response.status === 401) {
            await SafeVaultAuth.logout();
            return;
        }
        if (!response.ok) {
            const result = await response.json().catch(() => ({}));
            personalDataUnlockError.textContent = result.message ?? "Die persönlichen Daten konnten nicht geladen werden.";
            personalDataUnlockError.hidden = false;
            return;
        }

        const result = await response.json();
        personalDataInput.value = result.personalData;
        personalDataUnlockDialog.close();
        personalDataDialog.showModal();
        personalDataInput.focus();
    } catch {
        personalDataUnlockError.textContent = "SafeVault ist momentan nicht erreichbar.";
        personalDataUnlockError.hidden = false;
    } finally {
        submitButton.disabled = false;
    }
});

personalDataForm.addEventListener("submit", async event => {
    event.preventDefault();
    const submitButton = personalDataForm.querySelector('button[type="submit"]');
    submitButton.disabled = true;
    personalDataStatus.classList.remove("error");
    personalDataStatus.textContent = "Daten werden gespeichert …";

    try {
        const response = await SafeVaultAuth.fetchWithAuth("/api/users/personal-data", {
            method: "PUT",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ personalData: personalDataInput.value })
        });

        if (!response.ok) {
            const result = await response.json().catch(() => ({}));
            throw new Error(result.message ?? "Die persönlichen Daten konnten nicht gespeichert werden.");
        }
        personalDataStatus.textContent = "Die persönlichen Daten wurden gespeichert.";
    } catch (error) {
        personalDataStatus.classList.add("error");
        personalDataStatus.textContent = error.message ?? "SafeVault ist momentan nicht erreichbar.";
    } finally {
        submitButton.disabled = false;
    }
});
