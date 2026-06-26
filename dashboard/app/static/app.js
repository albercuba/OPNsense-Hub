document.addEventListener("DOMContentLoaded", () => {
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
    table
      .querySelectorAll(".dashboard-sort-indicator")
      .forEach((indicator, index) => {
        indicator.textContent =
          index === activeIndex ? (direction === "asc" ? "▲" : "▼") : "↕";
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
        button.innerHTML = `<span>${escapeHtml(label)}</span><span class="dashboard-sort-indicator" aria-hidden="true">↕</span>`;
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
    target?.scrollIntoView({ behavior: "smooth", block: "start" });
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
  document.querySelectorAll("[data-dashboard-card-kind]").forEach((card) => {
    card.addEventListener("click", () => {
      const kind = card.dataset.dashboardCardKind;
      const scrollTarget = card.dataset.dashboardScroll;
      if (kind === "status" && filterForm) {
        const select = filterForm.querySelector("select[name='status']");
        if (select) {
          select.value = card.dataset.dashboardStatus || "";
          filterForm.submit();
          return;
        }
      }
      if (kind === "table") {
        applyTableFilter(
          card.dataset.targetTable,
          card.dataset.filterColumn,
          card.dataset.filterValue,
        );
        scrollToTarget(scrollTarget);
      }
    });
  });

  const updateElapsedTimestamp = () => {
    const label = document.querySelector("[data-dashboard-last-updated]");
    if (!label) {
      return;
    }
    const startedAt = Number(label.dataset.startedAt || Date.now());
    const seconds = Math.max(0, Math.floor((Date.now() - startedAt) / 1000));
    label.textContent =
      seconds < 5
        ? "just now"
        : `${seconds} second${seconds === 1 ? "" : "s"} ago`;
  };

  const lastUpdatedLabel = document.querySelector(
    "[data-dashboard-last-updated]",
  );
  if (lastUpdatedLabel) {
    lastUpdatedLabel.dataset.startedAt = String(Date.now());
    updateElapsedTimestamp();
    window.setInterval(updateElapsedTimestamp, 1000);
  }

  document
    .querySelector("[data-dashboard-refresh]")
    ?.addEventListener("click", () => {
      window.location.reload();
    });

  document.querySelectorAll("[data-export-table]").forEach((button) => {
    button.addEventListener("click", () => {
      const table = document.querySelector(button.dataset.exportTable || "");
      if (!table) {
        return;
      }
      const headers = Array.from(table.querySelectorAll("thead th")).map(
        (header) => header.textContent.trim(),
      );
      const rows = Array.from(table.tBodies[0]?.rows || [])
        .filter(
          (row) =>
            row.dataset.rowHidden !== "true" &&
            !row.querySelector(".table-empty-state"),
        )
        .map((row) =>
          Array.from(row.cells).map(
            (cell) => `"${cell.textContent.replace(/"/g, '""').trim()}"`,
          ),
        );
      const csv = [headers, ...rows].map((row) => row.join(",")).join("\n");
      const blob = new Blob([csv], { type: "text/csv;charset=utf-8;" });
      const url = URL.createObjectURL(blob);
      const link = document.createElement("a");
      link.href = url;
      link.download = button.dataset.exportFilename || "export.csv";
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    });
  });

  const recentEventsTable = document.querySelector("#recent-events-table");
  const rangeSelect = document.querySelector("[data-events-range-select]");
  const customRange = document.querySelector("[data-events-custom-range]");
  const customStart = document.querySelector("[data-events-start]");
  const customEnd = document.querySelector("[data-events-end]");

  const applyRecentEventsRange = () => {
    if (!recentEventsTable || !rangeSelect) {
      return;
    }
    const selectedRange = rangeSelect.value;
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
});
