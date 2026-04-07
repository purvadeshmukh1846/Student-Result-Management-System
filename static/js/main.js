// Auto-hide alerts after 5 seconds
document.addEventListener("DOMContentLoaded", function () {
  setTimeout(function () {
    document.querySelectorAll(".alert").forEach((alert) => {
      alert.style.transition = "opacity 0.5s";
      alert.style.opacity = "0";
      setTimeout(() => alert.remove(), 500);
    });
  }, 5000);

  // Add active class to current nav link
  const current = window.location.pathname;
  document.querySelectorAll(".navbar-menu a").forEach((link) => {
    if (link.getAttribute("href") === current) {
      link.classList.add("active");
    }
  });
});

// Confirm delete actions (if any)
document.querySelectorAll(".delete-confirm").forEach((btn) => {
  btn.addEventListener("click", (e) => {
    if (!confirm("Are you sure you want to delete this item?")) {
      e.preventDefault();
    }
  });
});
