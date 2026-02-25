(function () {
  const setScrollOnSubmit = (form) => {
    const input = form.querySelector("input[name='scroll_y']");
    if (input) {
      input.value = String(window.scrollY || 0);
    }
  };

  const restorePosition = (container) => {
    const scrollRaw = container.dataset.scrollPosition || "";
    const focusRaw = container.dataset.focusUserId || "";
    const scrollValue = Number.parseInt(scrollRaw, 10);

    if (!Number.isNaN(scrollValue)) {
      window.scrollTo(0, scrollValue);
      return;
    }

    if (focusRaw) {
      const row = document.getElementById(`member-${focusRaw}`);
      if (row) {
        row.scrollIntoView({ block: "center" });
      }
    }
  };

  const clearFocusParams = () => {
    const url = new URL(window.location.href);
    const hadFocus = url.searchParams.has("focus") || url.searchParams.has("scroll");

    if (!hadFocus) {
      return;
    }

    url.searchParams.delete("focus");
    url.searchParams.delete("scroll");

    const query = url.searchParams.toString();
    const nextUrl = `${url.pathname}${query ? `?${query}` : ""}${url.hash}`;
    window.history.replaceState({}, "", nextUrl);
  };

  const bindDeleteConfirm = () => {
    const confirmButtons = document.querySelectorAll("[data-confirm-message]");
    confirmButtons.forEach((button) => {
      button.addEventListener("click", (event) => {
        const message = button.getAttribute("data-confirm-message") || "Are you sure?";
        if (!window.confirm(message)) {
          event.preventDefault();
        }
      });
    });
  };

  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll("form.preserve-scroll").forEach((form) => {
      form.addEventListener("submit", () => setScrollOnSubmit(form));
    });

    bindDeleteConfirm();

    const container = document.getElementById("admin-manage");
    if (!container) {
      return;
    }

    restorePosition(container);
    clearFocusParams();
  });
})();
