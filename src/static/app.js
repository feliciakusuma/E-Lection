(() => {
  document.addEventListener("submit", (event) => {
    const form = event.target;
    if (!(form instanceof HTMLFormElement)) return;
    const msg = form.getAttribute("data-confirm");
    if (msg && !window.confirm(msg)) {
      event.preventDefault();
      event.stopPropagation();
    }
  });

  document.addEventListener("click", (event) => {
    const submitBtn = event.target.closest("[data-submit-target]");
    if (submitBtn) {
      const target = submitBtn.getAttribute("data-submit-target");
      if (target) {
        const form = document.querySelector(target);
        if (form instanceof HTMLFormElement) {
          form.requestSubmit ? form.requestSubmit() : form.submit();
        }
      }
    }

    const toggleBtn = event.target.closest("[data-toggle-password]");
    if (toggleBtn) {
      const inputId = toggleBtn.getAttribute("data-toggle-password");
      if (!inputId) return;
      const input = document.getElementById(inputId);
      const icon = document.getElementById(inputId + "-eye");
      if (!(input instanceof HTMLInputElement)) return;
      if (input.type === "password") {
        input.type = "text";
        if (icon) {
          icon.classList.remove("fa-eye");
          icon.classList.add("fa-eye-slash");
        }
      } else {
        input.type = "password";
        if (icon) {
          icon.classList.remove("fa-eye-slash");
          icon.classList.add("fa-eye");
        }
      }
    }
  });

  document.addEventListener("change", (event) => {
    const el = event.target;
    if (el && el.matches && el.matches("[data-auto-submit='true']")) {
      const form = el.form;
      if (form) form.submit();
    }
  });

  document.querySelectorAll("[data-color]").forEach((el) => {
    const val = el.getAttribute("data-color");
    if (val) el.style.color = val;
  });
  document.querySelectorAll("[data-bg]").forEach((el) => {
    const val = el.getAttribute("data-bg");
    if (val) el.style.background = val;
  });
  document.querySelectorAll("[data-width]").forEach((el) => {
    const val = el.getAttribute("data-width");
    if (val) el.style.width = val;
  });
})();
