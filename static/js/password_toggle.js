(function () {
  const toggleButtons = document.querySelectorAll(".password-toggle[data-target]");

  toggleButtons.forEach((button) => {
    const targetId = button.getAttribute("data-target");
    const input = targetId ? document.getElementById(targetId) : null;
    if (!input) {
      return;
    }

    button.addEventListener("click", () => {
      const showPassword = input.type === "password";
      input.type = showPassword ? "text" : "password";
      button.setAttribute("aria-pressed", showPassword ? "true" : "false");
      button.setAttribute("aria-label", showPassword ? "Hide password" : "Show password");
      input.focus({ preventScroll: true });
    });
  });
})();
