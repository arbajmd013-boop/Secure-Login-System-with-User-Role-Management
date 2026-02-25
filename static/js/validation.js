(function () {
  const registerForm = document.getElementById("register-form");
  const loginForm = document.getElementById("login-form");
  const adminCreateForm = document.getElementById("admin-create-form");

  const isStrongPassword = (password) => {
    return (
      password.length >= 12 &&
      /[A-Z]/.test(password) &&
      /[a-z]/.test(password) &&
      /[0-9]/.test(password) &&
      /[^A-Za-z0-9]/.test(password)
    );
  };

  if (registerForm) {
    registerForm.addEventListener("submit", (event) => {
      const username = registerForm.username.value.trim();
      const email = registerForm.email.value.trim();
      const password = registerForm.password.value;
      const confirmPassword = registerForm.confirm_password.value;
      const roleInput = registerForm.querySelector("[name='role']");
      const role = roleInput ? roleInput.value : "user";

      const usernameOk = /^[A-Za-z0-9_]{3,30}$/.test(username);
      const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

      if (!usernameOk) {
        event.preventDefault();
        alert("Username should be 3-30 chars and only letters, numbers, underscores.");
        return;
      }

      if (!emailOk) {
        event.preventDefault();
        alert("Please enter a valid email address.");
        return;
      }

      if (!isStrongPassword(password)) {
        event.preventDefault();
        alert("Password must be at least 12 chars and include upper/lower/number/symbol.");
        return;
      }

      if (confirmPassword.length < 1) {
        event.preventDefault();
        alert("Please re-enter your password.");
        return;
      }

      if (password !== confirmPassword) {
        event.preventDefault();
        alert("Password and Re-enter Password must match.");
        return;
      }

      if (!["admin", "user"].includes(role)) {
        event.preventDefault();
        alert("Invalid role selected.");
      }
    });
  }

  if (adminCreateForm) {
    adminCreateForm.addEventListener("submit", (event) => {
      const username = adminCreateForm.username.value.trim();
      const email = adminCreateForm.email.value.trim();
      const password = adminCreateForm.password.value;
      const role = adminCreateForm.role.value;

      const usernameOk = /^[A-Za-z0-9_]{3,30}$/.test(username);
      const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

      if (!usernameOk) {
        event.preventDefault();
        alert("Username should be 3-30 chars and only letters, numbers, underscores.");
        return;
      }

      if (!emailOk) {
        event.preventDefault();
        alert("Please enter a valid email address.");
        return;
      }

      if (!isStrongPassword(password)) {
        event.preventDefault();
        alert("Password must be at least 12 chars and include upper/lower/number/symbol.");
        return;
      }

      if (!["admin", "user"].includes(role)) {
        event.preventDefault();
        alert("Invalid role selected.");
      }
    });
  }

  if (loginForm) {
    loginForm.addEventListener("submit", (event) => {
      const email = loginForm.email.value.trim();
      const password = loginForm.password.value;
      const captcha = loginForm.captcha_answer.value.trim();
      const emailOk = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

      if (!emailOk || password.length < 1 || captcha.length < 1) {
        event.preventDefault();
        alert("Please provide valid email, password, and CAPTCHA.");
      }
    });
  }
})();
