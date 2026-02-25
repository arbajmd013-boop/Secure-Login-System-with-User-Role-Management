(function () {
  const form = document.getElementById("achievement-upload-form");
  if (!form) {
    return;
  }

  const allowedExtensions = ["png", "jpg", "jpeg", "webp", "gif", "pdf"];
  const maxSize = 5 * 1024 * 1024;
  const fileInput = form.proof_file;
  const clearFileButton = document.getElementById("clear-proof-file");
  const fileNameHint = document.getElementById("proof-file-name");

  const updateSelectedFileState = () => {
    const file = fileInput.files && fileInput.files[0];
    if (clearFileButton) {
      clearFileButton.hidden = !file;
    }
    if (fileNameHint) {
      fileNameHint.textContent = file ? `Selected: ${file.name}` : "";
    }
  };

  if (fileInput) {
    fileInput.addEventListener("change", updateSelectedFileState);
  }

  if (clearFileButton && fileInput) {
    clearFileButton.addEventListener("click", () => {
      fileInput.value = "";
      updateSelectedFileState();
      fileInput.focus({ preventScroll: true });
    });
  }

  updateSelectedFileState();

  form.addEventListener("submit", (event) => {
    const title = form.title.value.trim();
    const description = form.description.value.trim();
    const achievedOn = form.achieved_on ? form.achieved_on.value.trim() : "";
    const file = fileInput.files && fileInput.files[0];

    if (title.length < 3 || title.length > 140) {
      event.preventDefault();
      alert("Title must be between 3 and 140 characters.");
      return;
    }

    if (description.length > 1200) {
      event.preventDefault();
      alert("Description should be 1200 characters or fewer.");
      return;
    }

    if (achievedOn) {
      const dateValue = new Date(`${achievedOn}T00:00:00`);
      if (Number.isNaN(dateValue.getTime())) {
        event.preventDefault();
        alert("Please provide a valid achievement date.");
        return;
      }
    }

    if (!file) {
      event.preventDefault();
      alert("Please select a file to upload.");
      return;
    }

    const fileName = file.name.toLowerCase();
    const extension = fileName.includes(".") ? fileName.split(".").pop() : "";
    if (!allowedExtensions.includes(extension)) {
      event.preventDefault();
      alert("Only PNG/JPG/JPEG/WEBP/GIF/PDF files are allowed.");
      return;
    }

    if (file.size <= 0 || file.size > maxSize) {
      event.preventDefault();
      alert("File size must be between 1 byte and 5 MB.");
    }
  });
})();
