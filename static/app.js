/* Cyberseek shared client behavior: theme, CSRF, local times, form feedback,
   history filters, and live task status updates. Loaded with `defer` on every page. */
(function () {
  "use strict";

  const body = document.body;
  const csrf = document.querySelector('meta[name="csrf-token"]')?.content;
  const ACTIVE = new Set(["Running", "Queued"]);

  /* ----- theme ----- */
  const storeTheme = (theme) => { try { localStorage.setItem("cyberseek-theme", theme); } catch (_) { /* storage unavailable */ } };
  document.querySelector(".theme-toggle")?.addEventListener("click", () => {
    const next = body.dataset.theme === "dark" ? "light" : "dark";
    body.dataset.theme = next;
    storeTheme(next);
  });

  /* ----- mobile menu ----- */
  const menuToggle = document.querySelector(".menu-toggle");
  menuToggle?.addEventListener("click", () => {
    const open = body.classList.toggle("menu-open");
    menuToggle.setAttribute("aria-expanded", String(open));
    menuToggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
  });

  /* ----- CSRF token for every POST form ----- */
  if (csrf) {
    document.querySelectorAll("form").forEach((form) => {
      if (form.method.toLowerCase() !== "post" || form.querySelector('input[name="csrf_token"]')) return;
      const input = document.createElement("input");
      input.type = "hidden"; input.name = "csrf_token"; input.value = csrf;
      form.prepend(input);
    });
  }

  /* ----- timestamps in the analyst's local time zone ----- */
  const thisYear = new Date().getFullYear();
  const shortFormat = new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
  const longFormat = new Intl.DateTimeFormat(undefined, { year: "numeric", month: "short", day: "numeric", hour: "numeric", minute: "2-digit" });
  const relative = typeof Intl.RelativeTimeFormat === "function" ? new Intl.RelativeTimeFormat(undefined, { numeric: "auto" }) : null;
  const relativeLabel = (date) => {
    if (!relative) return "";
    const seconds = (date.getTime() - Date.now()) / 1000;
    const steps = [[60, 1, "second"], [3600, 60, "minute"], [86400, 3600, "hour"], [2592000, 86400, "day"]];
    const step = steps.find(([limit]) => Math.abs(seconds) < limit);
    return step ? relative.format(Math.round(seconds / step[1]), step[2]) : "";
  };
  // Short local date in the text; relative age and exact UTC time on hover.
  const renderTimes = (root = document) => root.querySelectorAll("time[data-local-time]").forEach((node) => {
    const raw = node.getAttribute("datetime");
    const date = new Date(/[zZ]|[+-]\d\d:\d\d$/.test(raw) ? raw : raw + "Z");
    if (Number.isNaN(date.getTime())) return;
    node.textContent = (date.getFullYear() === thisYear ? shortFormat : longFormat).format(date);
    const ago = relativeLabel(date);
    node.title = `${ago ? ago + " · " : ""}${date.toISOString().slice(0, 16).replace("T", " ")} UTC`;
  });
  renderTimes();

  /* ----- confirmations and submit feedback ----- */
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (form.dataset.confirm && !window.confirm(form.dataset.confirm)) {
      event.preventDefault();
      return;
    }
    if (form.method.toLowerCase() !== "post") return;
    const button = event.submitter && event.submitter.classList.contains("primary") ? event.submitter : form.querySelector("button.primary");
    if (!button || button.dataset.busy) return;
    button.dataset.busy = "1";
    button.classList.add("is-busy");
    button.setAttribute("aria-busy", "true");
    // Disable after the browser has captured the submitter, so its name/value are still sent.
    window.setTimeout(() => { button.disabled = true; }, 0);
  });
  window.addEventListener("pageshow", (event) => {
    if (!event.persisted) return;
    document.querySelectorAll("button.is-busy").forEach((button) => {
      button.disabled = false; button.classList.remove("is-busy"); button.removeAttribute("aria-busy"); delete button.dataset.busy;
    });
  });

  /* ----- task history filters: selects and dates apply immediately ----- */
  document.querySelectorAll("[data-history-filters]").forEach((form) => {
    form.querySelectorAll("select, input[type=date]").forEach((field) => field.addEventListener("change", () => form.requestSubmit()));
    form.addEventListener("submit", () => {
      form.querySelectorAll("input, select").forEach((field) => { if (!field.value) field.disabled = true; });
    });
  });

  /* ----- "/" focuses the global search ----- */
  const search = document.querySelector("[data-global-search]");
  document.addEventListener("keydown", (event) => {
    if (event.key !== "/" || !search || event.metaKey || event.ctrlKey || event.altKey) return;
    const target = event.target instanceof Element ? event.target : null;
    if (target?.closest("input, textarea, select, [contenteditable=true]")) return;
    event.preventDefault();
    search.focus();
    search.select();
  });

  /* ----- live task status ----- */
  const setBadge = (badge, status) => {
    badge.dataset.taskStatus = status;
    badge.className = `task-status ${status.toLowerCase()}`;
    const dot = badge.querySelector(".status-dot");
    badge.textContent = status;
    if (dot) badge.prepend(dot);
  };
  const poll = (url, ids, onUpdate) => {
    let delay = 3000;
    const tick = async () => {
      const pending = ids();
      if (!pending.length) return;
      try {
        const response = await fetch(`${url}?ids=${encodeURIComponent(pending.join(","))}`, { headers: { Accept: "application/json" }, credentials: "same-origin" });
        if (!response.ok) throw new Error(String(response.status));
        onUpdate((await response.json()).tasks || {});
        delay = 3000;
      } catch (_) {
        delay = Math.min(delay * 2, 30000);
      }
      if (!document.hidden) window.setTimeout(tick, delay);
      else document.addEventListener("visibilitychange", () => window.setTimeout(tick, 500), { once: true });
    };
    window.setTimeout(tick, delay);
  };

  // History lists: update badges and the "Active" counter in place.
  document.querySelectorAll("[data-history][data-status-url]").forEach((history) => {
    const activeIds = () => [...history.querySelectorAll("[data-task-row]")]
      .filter((row) => ACTIVE.has(row.querySelector("[data-task-status]")?.dataset.taskStatus))
      .map((row) => row.dataset.taskId);
    const counter = history.querySelector('[data-stat="active"]');
    poll(history.dataset.statusUrl, activeIds, (tasks) => {
      Object.entries(tasks).forEach(([id, status]) => {
        const row = history.querySelector(`[data-task-row][data-task-id="${CSS.escape(id)}"]`);
        const badge = row?.querySelector("[data-task-status]");
        if (!badge || badge.dataset.taskStatus === status) return;
        if (counter && ACTIVE.has(badge.dataset.taskStatus) && !ACTIVE.has(status)) {
          counter.textContent = String(Math.max(0, Number(counter.textContent) - 1));
        }
        setBadge(badge, status);
        row.classList.add("is-updated");
      });
    });
  });

  // Task reports: reload once when the task this page shows finishes.
  const liveUrl = body.dataset.taskStatusUrl;
  const liveId = body.dataset.taskId;
  const liveBadge = document.querySelector("[data-task-status]");
  if (liveUrl && liveId && liveBadge && ACTIVE.has(liveBadge.dataset.taskStatus)) {
    const initial = liveBadge.dataset.taskStatus;
    poll(liveUrl, () => (ACTIVE.has(liveBadge.dataset.taskStatus) ? [liveId] : []), (tasks) => {
      const status = tasks[liveId];
      if (status && status !== initial) {
        liveBadge.dataset.taskStatus = status;
        window.location.reload();
      }
    });
  }

  /* ----- report tabs (role=tablist with data-report-tab buttons) ----- */
  document.querySelectorAll("[role=tablist]").forEach((list) => {
    list.addEventListener("keydown", (event) => {
      if (!["ArrowLeft", "ArrowRight"].includes(event.key)) return;
      const tabs = [...list.querySelectorAll("[role=tab]")];
      const index = tabs.indexOf(document.activeElement);
      if (index < 0) return;
      const next = tabs[(index + (event.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
      next.focus();
      next.click();
    });
  });
})();
