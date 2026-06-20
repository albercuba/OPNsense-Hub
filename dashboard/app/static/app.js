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
});
