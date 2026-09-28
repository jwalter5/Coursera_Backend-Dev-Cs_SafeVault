"use strict";

SafeVaultAuth.showCurrentUser();
SafeVaultAuth.bindChangePasswordDialog();
SafeVaultAuth.bindDeleteAccountDialog();
document.getElementById("logout").addEventListener("click", SafeVaultAuth.logout);

const personalDataForm = document.getElementById("personal-data-form");
const personalDataInput = document.getElementById("personal-data");
const personalDataStatus = document.getElementById("personal-data-status");

async function loadPersonalData() {
    const response = await SafeVaultAuth.fetchWithAuth("/api/users/personal-data");
    if (response.status === 401) {
        return;
    }
    if (!response.ok) {
        throw new Error("Personal data could not be loaded.");
    }

    const result = await response.json();
    personalDataInput.value = result.personalData;
}

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

loadPersonalData().catch(() => {
    personalDataStatus.classList.add("error");
    personalDataStatus.textContent = "Die persönlichen Daten konnten nicht geladen werden.";
});
