document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll("[data-company-row]").forEach((row) => {
    const firewallsRow = row.nextElementSibling;
    const toggle = () => {
      if (!firewallsRow || !firewallsRow.matches("[data-company-firewalls]")) {
        return;
      }
      const expanded = row.getAttribute("aria-expanded") === "true";
      row.setAttribute("aria-expanded", String(!expanded));
      firewallsRow.hidden = expanded;
    };

    row.addEventListener("click", (event) => {
      if (event.target.closest("a, button, form")) {
        return;
      }
      toggle();
    });
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        toggle();
      }
    });
  });

  document.querySelectorAll("[data-editable-row]").forEach((row) => {
    const editButton = row.querySelector("[data-edit-button]");
    const saveButton = row.querySelector("[data-save-button]");
    const controls = row.querySelectorAll("[data-edit-control]");

    if (!editButton || !saveButton || controls.length === 0) {
      return;
    }

    editButton.addEventListener("click", () => {
      controls.forEach((control) => {
        control.disabled = false;
      });
      row.classList.add("editing");
      editButton.hidden = true;
      saveButton.hidden = false;
      controls[0].focus();
      if (typeof controls[0].select === "function") {
        controls[0].select();
      }
    });
  });

  const closeEnrollmentDialog = () => {
    document.querySelector("[data-enrollment-dialog]")?.remove();
  };

  const escapeHtml = (value) =>
    String(value || "").replace(
      /[&<>'"]/g,
      (character) =>
        ({
          "&": "&amp;",
          "<": "&lt;",
          ">": "&gt;",
          "'": "&#39;",
          '"': "&quot;",
        })[character],
    );

  const showEnrollmentDialog = ({
    code,
    company,
    expires_at_display: expiresAt,
  }) => {
    closeEnrollmentDialog();
    const dialog = document.createElement("div");
    dialog.className = "modal-backdrop";
    dialog.dataset.enrollmentDialog = "true";
    dialog.innerHTML = `
      <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="enrollment-dialog-title">
        <button class="modal-close" type="button" data-close-enrollment-dialog aria-label="Close"><i class="fa-solid fa-xmark"></i></button>
        <p class="eyebrow">Enrollment OTP</p>
        <h2 id="enrollment-dialog-title">${company ? `Code for ${escapeHtml(company)}` : "Enrollment code"}</h2>
        <p class="muted">Enter this code in the OPNsense Hub plugin. It is shown once, expires at ${escapeHtml(expiresAt)}, and is single-use.</p>
        <div class="otp-copy-row">
          <code class="otp-popup-code" data-enrollment-code>${escapeHtml(code)}</code>
          <button class="icon-button" type="button" data-copy-enrollment-code title="Copy code" aria-label="Copy code"><i class="fa-solid fa-copy"></i></button>
        </div>
        <p class="copy-feedback muted" data-copy-feedback hidden>Copied.</p>
      </div>
    `;
    dialog.addEventListener("click", (event) => {
      if (
        event.target === dialog ||
        event.target.closest("[data-close-enrollment-dialog]")
      ) {
        closeEnrollmentDialog();
      }
    });
    dialog
      .querySelector("[data-copy-enrollment-code]")
      ?.addEventListener("click", async () => {
        const feedback = dialog.querySelector("[data-copy-feedback]");
        try {
          await navigator.clipboard.writeText(code);
          if (feedback) {
            feedback.hidden = false;
          }
        } catch (error) {
          window.prompt("Copy enrollment code", code);
        }
      });
    document.body.appendChild(dialog);
    dialog.querySelector("[data-copy-enrollment-code]")?.focus();
  };

  document.querySelectorAll("[data-enrollment-form]").forEach((form) => {
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submitter =
        event.submitter || form.querySelector("button[type='submit']");
      if (submitter) {
        submitter.disabled = true;
      }
      try {
        const response = await fetch(form.action, {
          method: "POST",
          headers: { Accept: "application/json" },
          credentials: "same-origin",
        });
        if (!response.ok) {
          throw new Error(`Request failed with status ${response.status}`);
        }
        showEnrollmentDialog(await response.json());
      } catch (error) {
        form.submit();
      } finally {
        if (submitter) {
          submitter.disabled = false;
        }
      }
    });
  });
});
