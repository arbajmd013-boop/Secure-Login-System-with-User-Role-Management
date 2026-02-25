(function () {
  const STORAGE_KEY = "secureauth-theme";

  const isValidTheme = (value) => value === "dark" || value === "light";

  const getStoredTheme = () => {
    try {
      const value = localStorage.getItem(STORAGE_KEY);
      return isValidTheme(value) ? value : null;
    } catch (_error) {
      return null;
    }
  };

  const getSystemTheme = () => {
    return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  };

  const applyTheme = (theme) => {
    document.documentElement.setAttribute("data-theme", theme);
  };

  const saveTheme = (theme) => {
    try {
      localStorage.setItem(STORAGE_KEY, theme);
    } catch (_error) {
      // Ignore write errors in restricted browsers.
    }
  };

  const activeTheme = getStoredTheme() || getSystemTheme();
  applyTheme(activeTheme);

  const updateToggleButton = () => {
    const button = document.getElementById("theme-toggle");
    if (!button) {
      return;
    }

    const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
    const nextTheme = currentTheme === "dark" ? "light" : "dark";
    button.textContent = nextTheme === "dark" ? "Dark" : "Light";
    button.setAttribute("aria-label", `Switch to ${nextTheme} mode`);
  };

  const toggleTheme = () => {
    const currentTheme = document.documentElement.getAttribute("data-theme") || "light";
    const nextTheme = currentTheme === "dark" ? "light" : "dark";
    applyTheme(nextTheme);
    saveTheme(nextTheme);
    updateToggleButton();
  };

  document.addEventListener("DOMContentLoaded", () => {
    const button = document.getElementById("theme-toggle");
    if (button) {
      button.addEventListener("click", toggleTheme);
    }
    updateToggleButton();
  });
})();
