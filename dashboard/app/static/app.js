document.addEventListener("DOMContentLoaded", () => {
  const themeToggle = document.querySelector("#theme-toggle");
  const root = document.documentElement;
  const storedTheme = window.localStorage.getItem("opnsense-hub-theme");
  const prefersDark = window.matchMedia("(prefers-color-scheme: dark)").matches;
  const initialTheme =
    storedTheme === "dark" || storedTheme === "light"
      ? storedTheme
      : prefersDark
        ? "dark"
        : "light";
  const initialDensity = "compact";

  const applyTheme = (theme, persist = true) => {
    root.dataset.theme = theme;
    if (themeToggle) {
      themeToggle.checked = theme === "dark";
      themeToggle.setAttribute("aria-checked", String(theme === "dark"));
    }
    if (persist) {
      window.localStorage.setItem("opnsense-hub-theme", theme);
    }
  };

  const applyDensity = () => {
    root.dataset.density = "compact";
  };

  applyTheme(initialTheme, false);
  applyDensity(initialDensity, false);
  themeToggle?.addEventListener("change", () => {
    applyTheme(themeToggle.checked ? "dark" : "light");
  });

  document.querySelectorAll("[data-toast]").forEach((toast) => {
    const dismiss = () => {
      toast.classList.add("is-closing");
      window.setTimeout(() => {
        toast.closest(".toast-stack")?.remove();
      }, 180);
    };
    toast
      .querySelector("[data-toast-close]")
      ?.addEventListener("click", dismiss);
    window.setTimeout(dismiss, 4200);
  });

  const sideMenu = document.querySelector("#primary-side-menu");
  const sideMenuToggle = document.querySelector("[data-side-menu-toggle]");
  const sideMenuBackdrop = document.querySelector("[data-side-menu-backdrop]");
  const closeSideMenu = () => {
    document.body.classList.remove("side-menu-open");
    sideMenuToggle?.setAttribute("aria-expanded", "false");
  };
  const openSideMenu = () => {
    document.body.classList.add("side-menu-open");
    sideMenuToggle?.setAttribute("aria-expanded", "true");
  };
  sideMenuToggle?.addEventListener("click", () => {
    if (document.body.classList.contains("side-menu-open")) {
      closeSideMenu();
    } else {
      openSideMenu();
    }
  });
  sideMenuBackdrop?.addEventListener("click", closeSideMenu);
  sideMenu?.querySelectorAll("a, summary").forEach((element) => {
    element.addEventListener("click", () => {
      if (window.matchMedia("(max-width: 900px)").matches) {
        closeSideMenu();
      }
    });
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      closeSideMenu();
    }
  });
  window.addEventListener("resize", () => {
    if (!window.matchMedia("(max-width: 900px)").matches) {
      closeSideMenu();
    }
  });

  const setCompanyRowExpanded = (row, expanded) => {
    const firewallsRow = row.nextElementSibling;
    if (!firewallsRow || !firewallsRow.matches("[data-company-firewalls]")) {
      return;
    }
    row.setAttribute("aria-expanded", String(expanded));
    firewallsRow.hidden = !expanded;
  };

  document.querySelectorAll("[data-company-row]").forEach((row) => {
    row.addEventListener("click", (event) => {
      if (event.target.closest("a, button, form")) {
        return;
      }
      const expanded = row.getAttribute("aria-expanded") === "true";
      setCompanyRowExpanded(row, !expanded);
    });
    row.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        const expanded = row.getAttribute("aria-expanded") === "true";
        setCompanyRowExpanded(row, !expanded);
      }
    });
  });

  const closeConfirmationDialog = () => {
    document.querySelector("[data-confirm-dialog]")?.remove();
  };

  const showConfirmationDialog = ({
    title,
    message,
    confirmLabel = "Delete",
    cancelLabel = "Cancel",
    onConfirm,
  }) => {
    closeConfirmationDialog();
    const dialog = document.createElement("div");
    dialog.className = "modal-backdrop";
    dialog.dataset.confirmDialog = "true";
    dialog.innerHTML = `
      <div class="modal-card" role="dialog" aria-modal="true" aria-labelledby="confirm-dialog-title">
        <button class="modal-close" type="button" data-close-confirm-dialog aria-label="Close"><i class="fa-solid fa-xmark"></i></button>
        <p class="eyebrow">Confirmation</p>
        <h2 id="confirm-dialog-title">${escapeHtml(title || "Confirm action")}</h2>
        <p class="muted">${escapeHtml(message || "Are you sure you want to continue?")}</p>
        <div class="login-actions">
          <button class="button secondary" type="button" data-cancel-confirm-dialog>${escapeHtml(cancelLabel)}</button>
          <button class="button danger-text" type="button" data-confirm-dialog-submit>${escapeHtml(confirmLabel)}</button>
        </div>
      </div>
    `;
    const close = () => closeConfirmationDialog();
    dialog.addEventListener("click", (event) => {
      if (
        event.target === dialog ||
        event.target.closest("[data-close-confirm-dialog]") ||
        event.target.closest("[data-cancel-confirm-dialog]")
      ) {
        close();
      }
    });
    dialog
      .querySelector("[data-confirm-dialog-submit]")
      ?.addEventListener("click", () => {
        close();
        onConfirm?.();
      });
    document.addEventListener(
      "keydown",
      (event) => {
        if (event.key === "Escape") {
          close();
        }
      },
      { once: true },
    );
    document.body.appendChild(dialog);
    dialog.querySelector("[data-confirm-dialog-submit]")?.focus();
  };

  document.querySelectorAll("form[data-confirm-message]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      if (form.dataset.confirmedSubmit === "true") {
        delete form.dataset.confirmedSubmit;
        return;
      }
      const message = form.dataset.confirmMessage;
      if (!message) {
        return;
      }
      event.preventDefault();
      const submitter =
        event.submitter ||
        form.querySelector("button[type='submit'], input[type='submit']");
      const actionLabel =
        submitter?.getAttribute("aria-label") ||
        submitter?.getAttribute("title") ||
        "Confirm action";
      const confirmLabel = /delete|remove|revoke/i.test(actionLabel)
        ? actionLabel
        : "Confirm";
      showConfirmationDialog({
        title: actionLabel,
        message,
        confirmLabel,
        onConfirm: () => {
          form.dataset.confirmedSubmit = "true";
          if (submitter instanceof HTMLElement) {
            form.requestSubmit(submitter);
          } else {
            form.requestSubmit();
          }
        },
      });
    });
  });

  document.querySelectorAll("[data-editable-row]").forEach((row) => {
    const editButton = row.querySelector("[data-edit-button]");
    const saveButton = row.querySelector("[data-save-button]");
    const controls = row.querySelectorAll("[data-edit-control]");

    if (!editButton || !saveButton || controls.length === 0) {
      return;
    }

    const startEditing = () => {
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
    };

    editButton.addEventListener("click", startEditing);
    row.addEventListener("keydown", (event) => {
      if (
        (event.key === "Enter" || event.key === " ") &&
        event.target === editButton
      ) {
        event.preventDefault();
        startEditing();
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

  const companiesFilterForm = document.querySelector("[data-company-filters]");
  const companyNameFilter = document.querySelector(
    "[data-company-filter-name]",
  );
  const companyVersionFilter = document.querySelector(
    "[data-company-filter-version]",
  );
  const companyIpFilter = document.querySelector("[data-company-filter-ip]");

  const applyCompanyFilters = () => {
    if (!companiesFilterForm) {
      return;
    }
    const selectedCompany = (companyNameFilter?.value || "")
      .trim()
      .toLowerCase();
    const versionQuery = (companyVersionFilter?.value || "")
      .trim()
      .toLowerCase();
    const ipQuery = (companyIpFilter?.value || "").trim().toLowerCase();

    document.querySelectorAll("[data-company-row]").forEach((companyRow) => {
      const companyName = (companyRow.dataset.companyName || "").trim();
      const detailRow = companyRow.nextElementSibling;
      const deviceRows = Array.from(
        detailRow?.querySelectorAll("[data-device-row]") || [],
      );
      const companyMatches =
        !selectedCompany || companyName.includes(selectedCompany);

      let visibleDevices = 0;
      deviceRows.forEach((deviceRow) => {
        const versionMatches =
          !versionQuery ||
          (deviceRow.dataset.opnsenseVersion || "").includes(versionQuery) ||
          (deviceRow.dataset.pluginVersion || "").includes(versionQuery);
        const ipMatches =
          !ipQuery || (deviceRow.dataset.deviceIp || "").includes(ipQuery);
        const visible = companyMatches && versionMatches && ipMatches;
        deviceRow.dataset.deviceHidden = visible ? "false" : "true";
        if (visible) {
          visibleDevices += 1;
        }
      });

      const hasDeviceFilters = Boolean(versionQuery || ipQuery);
      const showCompany =
        companyMatches && (!hasDeviceFilters || visibleDevices > 0);
      companyRow.dataset.companyHidden = showCompany ? "false" : "true";
      if (detailRow?.matches("[data-company-firewalls]")) {
        detailRow.dataset.companyHidden = showCompany ? "false" : "true";
      }

      if (!showCompany) {
        setCompanyRowExpanded(companyRow, false);
      } else if (hasDeviceFilters || selectedCompany) {
        setCompanyRowExpanded(companyRow, true);
      }
    });
  };

  companyNameFilter?.addEventListener("input", applyCompanyFilters);
  companyNameFilter?.addEventListener("change", applyCompanyFilters);
  companyVersionFilter?.addEventListener("input", applyCompanyFilters);
  companyIpFilter?.addEventListener("input", applyCompanyFilters);
  companiesFilterForm?.addEventListener("reset", () => {
    window.setTimeout(applyCompanyFilters, 0);
  });
  applyCompanyFilters();

  document
    .querySelectorAll("[data-exclusive-email-toggle]")
    .forEach((input) => {
      input.addEventListener("change", () => {
        if (!input.checked) {
          return;
        }
        const peerName = input.dataset.exclusiveEmailToggle;
        if (!peerName) {
          return;
        }
        const peer = document.querySelector(`input[name='${peerName}']`);
        if (peer) {
          peer.checked = false;
        }
      });
    });

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
          body: new FormData(form),
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

  const parseSortableValue = (cell) => {
    const explicitValue = cell?.dataset?.sortValue;
    const value = (explicitValue ?? cell?.textContent ?? "").trim();
    const numericValue = Number(value.replace(/,/g, ""));
    if (value !== "" && !Number.isNaN(numericValue)) {
      return { type: "number", value: numericValue };
    }
    const timestamp = Date.parse(value);
    if (!Number.isNaN(timestamp)) {
      return { type: "date", value: timestamp };
    }
    return { type: "text", value: value.toLowerCase() };
  };

  const updateSortIndicators = (table, activeIndex, direction) => {
    table.querySelectorAll("thead th").forEach((headerCell, index) => {
      const indicator = headerCell.querySelector(".dashboard-sort-indicator");
      if (indicator) {
        indicator.textContent =
          index === activeIndex ? (direction === "asc" ? "▲" : "▼") : "↕";
      }
      headerCell.setAttribute(
        "aria-sort",
        index === activeIndex
          ? direction === "asc"
            ? "ascending"
            : "descending"
          : "none",
      );
    });
  };

  document
    .querySelectorAll(
      "table[data-enhanced-table], .firewalls-management-table, .nested-table, table",
    )
    .forEach((table) => {
      const headerCells = Array.from(table.querySelectorAll("thead th"));
      const body = table.tBodies[0];
      if (!body || headerCells.length === 0) {
        return;
      }

      headerCells.forEach((headerCell, index) => {
        if (headerCell.classList.contains("actions")) {
          return;
        }
        const label = headerCell.textContent.trim();
        if (!label) {
          return;
        }
        const button = document.createElement("button");
        button.type = "button";
        button.className = "dashboard-sort-button";
        button.setAttribute("aria-label", `Sort by ${label}`);
        button.innerHTML = `<span>${escapeHtml(label)}</span><span class="dashboard-sort-indicator" aria-hidden="true">↕</span>`;
        headerCell.textContent = "";
        headerCell.appendChild(button);
        +headerCell.setAttribute("aria-sort", "none");
        headerCell.textContent = "";
        headerCell.appendChild(button);

        button.addEventListener("click", () => {
          const currentIndex = Number(table.dataset.sortColumn || -1);
          const currentDirection = table.dataset.sortDirection || "asc";
          const nextDirection =
            currentIndex === index && currentDirection === "asc"
              ? "desc"
              : "asc";
          table.dataset.sortColumn = String(index);
          table.dataset.sortDirection = nextDirection;

          const rows = Array.from(body.rows);
          rows.sort((leftRow, rightRow) => {
            const leftCell = leftRow.cells[index];
            const rightCell = rightRow.cells[index];
            const left = parseSortableValue(leftCell);
            const right = parseSortableValue(rightCell);
            const directionFactor = nextDirection === "asc" ? 1 : -1;

            if (left.type === right.type) {
              if (left.value < right.value) return -1 * directionFactor;
              if (left.value > right.value) return 1 * directionFactor;
              return 0;
            }
            return (
              String(left.value).localeCompare(String(right.value)) *
              directionFactor
            );
          });
          rows.forEach((row) => body.appendChild(row));
          updateSortIndicators(table, index, nextDirection);
        });
      });
    });

  const scrollToTarget = (selector) => {
    if (!selector) {
      return;
    }
    const target = document.querySelector(selector);
    if (!target) {
      return;
    }
    if (target.matches("details")) {
      target.open = true;
    } else {
      target
        .querySelector("[data-dashboard-collapsible]")
        ?.setAttribute("open", "open");
    }
    target.scrollIntoView({ behavior: "smooth", block: "start" });
  };

  const setTableRowVisibility = (table, predicate) => {
    const rows = Array.from(table.tBodies[0]?.rows || []);
    rows.forEach((row) => {
      const isEmptyStateRow = row.querySelector(".table-empty-state");
      if (isEmptyStateRow) {
        row.dataset.rowHidden = "false";
        return;
      }
      row.dataset.rowHidden = predicate(row) ? "false" : "true";
    });
  };

  const applyTableFilter = (tableSelector, columnName, expectedValue) => {
    const table = document.querySelector(tableSelector);
    if (!table) {
      return;
    }
    if (!columnName || !expectedValue) {
      setTableRowVisibility(table, () => true);
      return;
    }
    setTableRowVisibility(table, (row) => {
      const matchingCell = row.querySelector(`[data-column="${columnName}"]`);
      return matchingCell
        ? matchingCell.textContent.trim().toLowerCase() ===
            expectedValue.trim().toLowerCase()
        : true;
    });
  };

  const filterForm = document.querySelector("[data-dashboard-filter-form]");
  const dashboardCompanyInput = document.querySelector(
    "[data-dashboard-company-input]",
  );
  const dashboardCompanyId = document.querySelector(
    "[data-dashboard-company-id]",
  );
  const dashboardStatusInput = document.querySelector(
    "[data-dashboard-status-input]",
  );
  const dashboardStatusValue = document.querySelector(
    "[data-dashboard-status-value]",
  );

  const resolveDatalistOption = (listId, textValue) => {
    const normalized = (textValue || "").trim().toLowerCase();
    if (!normalized) {
      return null;
    }
    const options = Array.from(document.querySelectorAll(`#${listId} option`));
    return (
      options.find(
        (option) => option.value.trim().toLowerCase() === normalized,
      ) || null
    );
  };

  const resolveDatalistValue = (listId, textValue, dataAttribute) =>
    resolveDatalistOption(listId, textValue)?.dataset?.[dataAttribute] || "";

  const syncDashboardFilterInputs = () => {
    if (dashboardCompanyId) {
      dashboardCompanyId.value = resolveDatalistValue(
        "dashboard-company-options",
        dashboardCompanyInput?.value,
        "companyId",
      );
    }
    if (dashboardStatusValue) {
      dashboardStatusValue.value = resolveDatalistValue(
        "dashboard-status-options",
        dashboardStatusInput?.value,
        "statusValue",
      );
    }
  };

  let dashboardFilterSubmitTimer = null;
  const submitDashboardFilters = () => {
    syncDashboardFilterInputs();
    filterForm?.requestSubmit();
  };
  const scheduleDashboardFilterSubmit = (delay = 250) => {
    if (!filterForm) {
      return;
    }
    if (dashboardFilterSubmitTimer) {
      window.clearTimeout(dashboardFilterSubmitTimer);
    }
    dashboardFilterSubmitTimer = window.setTimeout(() => {
      dashboardFilterSubmitTimer = null;
      submitDashboardFilters();
    }, delay);
  };

  dashboardCompanyInput?.addEventListener("input", () => {
    syncDashboardFilterInputs();
    scheduleDashboardFilterSubmit();
  });
  dashboardCompanyInput?.addEventListener("change", submitDashboardFilters);
  dashboardStatusInput?.addEventListener("input", () => {
    syncDashboardFilterInputs();
    scheduleDashboardFilterSubmit();
  });
  dashboardStatusInput?.addEventListener("change", submitDashboardFilters);
  filterForm?.addEventListener("submit", syncDashboardFilterInputs);
  syncDashboardFilterInputs();

  const dashboardUiStateKey = `opnsense-hub-dashboard-ui:${window.location.pathname}${window.location.search}`;
  const readDashboardUiState = () => {
    try {
      return JSON.parse(
        window.sessionStorage.getItem(dashboardUiStateKey) || "{}",
      );
    } catch (_error) {
      return {};
    }
  };
  const writeDashboardUiState = (nextState) => {
    const currentState = readDashboardUiState();
    window.sessionStorage.setItem(
      dashboardUiStateKey,
      JSON.stringify({ ...currentState, ...nextState }),
    );
  };
  const detailsStateKey = (details, index) =>
    details.id ||
    details.dataset.dashboardStateKey ||
    details.querySelector("summary")?.textContent?.trim() ||
    `details-${index}`;

  const closeNotificationFailuresDialog = () => {
    document.querySelector("[data-notification-failures-dialog]")?.remove();
    writeDashboardUiState({ notificationFailuresDialogOpen: false });
  };

  const showNotificationFailuresDialog = () => {
    closeNotificationFailuresDialog();
    const template = document.querySelector(
      "#dashboard-notification-failures-template",
    );
    if (!template || !template.content) {
      return;
    }
    const dialog = document.createElement("div");
    dialog.className = "modal-backdrop";
    dialog.dataset.notificationFailuresDialog = "true";
    dialog.appendChild(template.content.cloneNode(true));
    dialog.addEventListener("click", (event) => {
      if (
        event.target === dialog ||
        event.target.closest("[data-close-notification-failures-dialog]")
      ) {
        closeNotificationFailuresDialog();
      }
    });
    document.addEventListener(
      "keydown",
      (event) => {
        if (event.key === "Escape") {
          closeNotificationFailuresDialog();
        }
      },
      { once: true },
    );
    document.body.appendChild(dialog);
    writeDashboardUiState({ notificationFailuresDialogOpen: true });
    dialog
      .querySelectorAll("form[action='/dashboard/attention/acknowledge']")
      .forEach((form) => {
        form.addEventListener("submit", () => {
          writeDashboardUiState({ notificationFailuresDialogOpen: true });
        });
      });
    dialog.querySelector("[data-close-notification-failures-dialog]")?.focus();
  };

  const handleDashboardCardAction = (card) => {
    const kind = card.dataset.dashboardCardKind;
    const scrollTarget = card.dataset.dashboardScroll;
    if (kind === "status" && filterForm) {
      if (dashboardStatusValue) {
        const targetStatus = card.dataset.dashboardStatus || "";
        dashboardStatusValue.value = targetStatus;
        if (dashboardStatusInput) {
          dashboardStatusInput.value =
            targetStatus === "online"
              ? "Online"
              : targetStatus === "warning"
                ? "Warning"
                : targetStatus === "critical"
                  ? "Critical"
                  : targetStatus === "revoked"
                    ? "Revoked"
                    : targetStatus === "other"
                      ? "Other / Unknown"
                      : "";
        }
        filterForm.submit();
        return;
      }
    }
    if (kind === "notification-failures") {
      showNotificationFailuresDialog();
      return;
    }
    if (kind === "table") {
      applyTableFilter(
        card.dataset.targetTable,
        card.dataset.filterColumn,
        card.dataset.filterValue,
      );
      scrollToTarget(scrollTarget);
    }
  };

  document.addEventListener("click", (event) => {
    const summaryCard = event.target.closest("[data-dashboard-card-kind]");
    if (summaryCard instanceof HTMLElement) {
      handleDashboardCardAction(summaryCard);
      return;
    }
    const failureCard = event.target.closest(
      "[data-notification-failures-trigger]",
    );
    if (failureCard instanceof HTMLElement) {
      showNotificationFailuresDialog();
    }
  });

  document.addEventListener("keydown", (event) => {
    const failureCard = event.target.closest?.(
      "[data-notification-failures-trigger]",
    );
    if (
      failureCard instanceof HTMLElement &&
      (event.key === "Enter" || event.key === " ")
    ) {
      event.preventDefault();
      showNotificationFailuresDialog();
    }
  });

  const dashboardUiState = readDashboardUiState();
  document
    .querySelectorAll("details[data-dashboard-collapsible], .dashboard-health-accordion details")
    .forEach((details, index) => {
      const stateKey = detailsStateKey(details, index);
      details.dataset.dashboardStateKey = stateKey;
      if (Object.prototype.hasOwnProperty.call(dashboardUiState, stateKey)) {
        details.open = Boolean(dashboardUiState[stateKey]);
      }
      details.addEventListener("toggle", () => {
        writeDashboardUiState({ [stateKey]: details.open });
      });
    });
  if (dashboardUiState.notificationFailuresDialogOpen) {
    showNotificationFailuresDialog();
  }

  const userFiltersForm = document.querySelector("[data-user-filters]");
  const userTable = document.querySelector("[data-user-table]");
  const userQueryInput = document.querySelector("[data-user-filter-query]");
  const userRoleInput = document.querySelector("[data-user-filter-role]");
  const userMfaInput = document.querySelector("[data-user-filter-mfa]");
  const userEmptyState = document.querySelector("[data-user-filter-empty]");

  const applyUserFilters = () => {
    if (!userTable) {
      return;
    }
    const query = (userQueryInput?.value || "").trim().toLowerCase();
    const role = resolveDatalistValue(
      "settings-user-filter-role-options",
      userRoleInput?.value,
      "roleValue",
    );
    const mfa = resolveDatalistValue(
      "settings-user-filter-mfa-options",
      userMfaInput?.value,
      "mfaValue",
    );
    let visibleRows = 0;

    userTable.querySelectorAll("[data-user-row]").forEach((row) => {
      const matchesQuery =
        !query || (row.dataset.userSearch || "").includes(query);
      const matchesRole = !role || (row.dataset.userRole || "") === role;
      const matchesMfa = !mfa || (row.dataset.userMfa || "") === mfa;
      const visible = matchesQuery && matchesRole && matchesMfa;
      row.dataset.userHidden = visible ? "false" : "true";
      if (visible) {
        visibleRows += 1;
      }
    });

    if (userEmptyState) {
      userEmptyState.hidden = visibleRows > 0;
    }
  };

  userQueryInput?.addEventListener("input", applyUserFilters);
  userRoleInput?.addEventListener("input", applyUserFilters);
  userRoleInput?.addEventListener("change", applyUserFilters);
  userMfaInput?.addEventListener("input", applyUserFilters);
  userMfaInput?.addEventListener("change", applyUserFilters);
  userFiltersForm?.addEventListener("reset", () => {
    window.setTimeout(applyUserFilters, 0);
  });
  applyUserFilters();

  const dashboardFiltersCard = document.querySelector(
    "[data-dashboard-revision]",
  );
  if (dashboardFiltersCard) {
    let currentRevision = dashboardFiltersCard.dataset.dashboardRevision || "0";
    let dashboardRefreshInFlight = false;
    const pollDashboardUpdates = async () => {
      if (document.hidden || dashboardRefreshInFlight) {
        return;
      }
      dashboardRefreshInFlight = true;
      try {
        const url = new URL("/dashboard/updates", window.location.origin);
        const params = new URLSearchParams(window.location.search);
        const companyId = params.get("company_id");
        const status = params.get("status");
        if (companyId) {
          url.searchParams.set("company_id", companyId);
        }
        if (status) {
          url.searchParams.set("status", status);
        }
        const response = await fetch(url, {
          headers: { Accept: "application/json" },
          credentials: "same-origin",
        });
        if (!response.ok) {
          return;
        }
        const payload = await response.json();
        const nextRevision = String(payload.revision || "0");
        if (nextRevision !== currentRevision) {
          window.location.reload();
          return;
        }
      } catch (_error) {
      } finally {
        dashboardRefreshInFlight = false;
      }
    };
    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) {
        pollDashboardUpdates();
      }
    });
    window.setInterval(pollDashboardUpdates, 10000);
    pollDashboardUpdates();
  }

  const savedFilterInput = document.querySelector(
    "[data-dashboard-saved-filter-input]",
  );
  const savedFilterApplyButton = document.querySelector(
    "[data-dashboard-saved-filter-apply]",
  );
  const savedFilterDeleteForm = document.querySelector(
    "[data-dashboard-saved-filter-delete-form]",
  );
  const savedFilterDeleteButton = document.querySelector(
    "[data-dashboard-saved-filter-delete]",
  );

  const syncSavedFilterControls = () => {
    const selectedOption = resolveDatalistOption(
      "dashboard-saved-filter-options",
      savedFilterInput?.value,
    );
    const selectedFilterId = selectedOption?.dataset.filterId || "";
    const selectedHref = selectedOption?.dataset.href || "";
    const hasSelection = Boolean(selectedFilterId && selectedHref);

    if (savedFilterApplyButton) {
      savedFilterApplyButton.disabled = !hasSelection;
    }
    if (savedFilterDeleteButton) {
      savedFilterDeleteButton.disabled = !hasSelection;
    }
    if (savedFilterDeleteForm) {
      const template = savedFilterDeleteForm.dataset.deleteActionTemplate || "";
      savedFilterDeleteForm.action = hasSelection
        ? template.replace("__FILTER_ID__", selectedFilterId)
        : "";
    }
  };

  savedFilterInput?.addEventListener("input", syncSavedFilterControls);
  savedFilterInput?.addEventListener("change", syncSavedFilterControls);
  savedFilterApplyButton?.addEventListener("click", () => {
    const selectedOption = resolveDatalistOption(
      "dashboard-saved-filter-options",
      savedFilterInput?.value,
    );
    const selectedHref = selectedOption?.dataset.href || "";
    if (selectedHref) {
      window.location.href = selectedHref;
    }
  });
  savedFilterDeleteForm?.addEventListener("submit", (event) => {
    if (!savedFilterDeleteForm.action) {
      event.preventDefault();
    }
  });
  syncSavedFilterControls();

  const createUserRoleInput = document.querySelector(
    "[data-create-user-role-input]",
  );
  const createUserRoleValue = document.querySelector(
    "[data-create-user-role-value]",
  );
  const createUserForm = createUserRoleInput?.closest("form") || null;
  const syncCreateUserRole = () => {
    if (createUserRoleValue) {
      createUserRoleValue.value =
        resolveDatalistValue(
          "settings-user-role-options",
          createUserRoleInput?.value,
          "roleValue",
        ) || "user";
    }
  };
  createUserRoleInput?.addEventListener("input", syncCreateUserRole);
  createUserRoleInput?.addEventListener("change", syncCreateUserRole);
  createUserForm?.addEventListener("submit", syncCreateUserRole);
  syncCreateUserRole();

  document.querySelectorAll("[data-user-edit-role-input]").forEach((input) => {
    const formId = input.getAttribute("form");
    if (!formId) {
      return;
    }
    const form = document.getElementById(formId);
    const hiddenValue = document.querySelector(
      `[data-user-edit-role-value][form="${formId}"]`,
    );
    const syncRole = () => {
      if (hiddenValue) {
        hiddenValue.value =
          resolveDatalistValue(
            "settings-user-role-options",
            input.value,
            "roleValue",
          ) || "user";
      }
    };
    input.addEventListener("input", syncRole);
    input.addEventListener("change", syncRole);
    form?.addEventListener("submit", syncRole);
    syncRole();
  });

  const backupIntervalUnitInput = document.querySelector(
    "[data-backup-interval-unit-input]",
  );
  const backupIntervalUnitValue = document.querySelector(
    "[data-backup-interval-unit-value]",
  );
  const backupSettingsForm = backupIntervalUnitInput?.closest("form") || null;
  const syncBackupIntervalUnit = () => {
    if (backupIntervalUnitValue) {
      backupIntervalUnitValue.value =
        resolveDatalistValue(
          "backup-interval-unit-options",
          backupIntervalUnitInput?.value,
          "unitValue",
        ) || "hours";
    }
  };
  backupIntervalUnitInput?.addEventListener("input", syncBackupIntervalUnit);
  backupIntervalUnitInput?.addEventListener("change", syncBackupIntervalUnit);
  backupSettingsForm?.addEventListener("submit", syncBackupIntervalUnit);
  syncBackupIntervalUnit();

  const recentEventsTable = document.querySelector("#recent-events-table");
  const rangeSelect = document.querySelector("[data-events-range-select]");
  const customRange = document.querySelector("[data-events-custom-range]");
  const customStart = document.querySelector("[data-events-start]");
  const customEnd = document.querySelector("[data-events-end]");

  const applyRecentEventsRange = () => {
    if (!recentEventsTable || !rangeSelect) {
      return;
    }
    const selectedRange =
      resolveDatalistValue(
        "dashboard-time-range-options",
        rangeSelect.value,
        "rangeValue",
      ) || "all";
    const now = Date.now();
    let minTimestamp = null;
    let maxTimestamp = null;

    if (selectedRange === "1h") {
      minTimestamp = now - 60 * 60 * 1000;
    } else if (selectedRange === "24h") {
      minTimestamp = now - 24 * 60 * 60 * 1000;
    } else if (selectedRange === "7d") {
      minTimestamp = now - 7 * 24 * 60 * 60 * 1000;
    } else if (selectedRange === "custom") {
      minTimestamp = customStart?.value ? Date.parse(customStart.value) : null;
      maxTimestamp = customEnd?.value ? Date.parse(customEnd.value) : null;
    }

    if (customRange) {
      customRange.hidden = selectedRange !== "custom";
    }

    setTableRowVisibility(recentEventsTable, (row) => {
      const rawTimestamp = row.dataset.eventTimestamp;
      if (!rawTimestamp) {
        return true;
      }
      const eventTimestamp = Date.parse(rawTimestamp);
      if (Number.isNaN(eventTimestamp)) {
        return true;
      }
      if (minTimestamp !== null && eventTimestamp < minTimestamp) {
        return false;
      }
      if (maxTimestamp !== null && eventTimestamp > maxTimestamp) {
        return false;
      }
      return true;
    });
  };

  rangeSelect?.addEventListener("change", applyRecentEventsRange);
  customStart?.addEventListener("change", applyRecentEventsRange);
  customEnd?.addEventListener("change", applyRecentEventsRange);
  applyRecentEventsRange();

  const auditLogTable = document.querySelector("#audit-log-table");
  const auditUserFilter = document.querySelector("[data-audit-user-filter]");
  const auditDeviceFilter = document.querySelector(
    "[data-audit-device-filter]",
  );
  const auditCompanyFilter = document.querySelector(
    "[data-audit-company-filter]",
  );
  const auditStart = document.querySelector("[data-audit-start]");
  const auditEnd = document.querySelector("[data-audit-end]");
  const auditFilterReset = document.querySelector("[data-audit-filter-reset]");

  const applyAuditLogFilters = () => {
    if (!auditLogTable) {
      return;
    }
    const userValue = (auditUserFilter?.value || "").trim().toLowerCase();
    const deviceValue = (auditDeviceFilter?.value || "").trim().toLowerCase();
    const companyValue = (auditCompanyFilter?.value || "").trim().toLowerCase();
    const minTimestamp = auditStart?.value
      ? Date.parse(auditStart.value)
      : null;
    const maxTimestamp = auditEnd?.value ? Date.parse(auditEnd.value) : null;

    setTableRowVisibility(auditLogTable, (row) => {
      const userText =
        row
          .querySelector('[data-column="audit-user"]')
          ?.textContent?.trim()
          .toLowerCase() || "";
      const deviceText =
        row
          .querySelector('[data-column="audit-device"]')
          ?.textContent?.trim()
          .toLowerCase() || "";
      const companyText =
        row
          .querySelector('[data-column="audit-company"]')
          ?.textContent?.trim()
          .toLowerCase() || "";
      if (userValue && !userText.includes(userValue)) {
        return false;
      }
      if (deviceValue && !deviceText.includes(deviceValue)) {
        return false;
      }
      if (companyValue && !companyText.includes(companyValue)) {
        return false;
      }
      const rawTimestamp = row.dataset.auditTimestamp;
      if (!rawTimestamp) {
        return true;
      }
      const eventTimestamp = Date.parse(rawTimestamp);
      if (Number.isNaN(eventTimestamp)) {
        return true;
      }
      if (minTimestamp !== null && eventTimestamp < minTimestamp) {
        return false;
      }
      if (maxTimestamp !== null && eventTimestamp > maxTimestamp) {
        return false;
      }
      return true;
    });
  };

  [auditUserFilter, auditDeviceFilter, auditCompanyFilter].forEach((input) => {
    input?.addEventListener("input", applyAuditLogFilters);
    input?.addEventListener("change", applyAuditLogFilters);
  });
  auditStart?.addEventListener("change", applyAuditLogFilters);
  auditEnd?.addEventListener("change", applyAuditLogFilters);
  auditFilterReset?.addEventListener("click", () => {
    window.setTimeout(() => {
      if (auditStart) {
        auditStart.value = "";
      }
      if (auditEnd) {
        auditEnd.value = "";
      }
      applyAuditLogFilters();
    }, 0);
  });
  applyAuditLogFilters();
});
