// Skrills client glue

// 1) Show submit modal on form submit so the user gets feedback during
//    ingest before the server-side redirect to the live status page.
document.addEventListener("DOMContentLoaded", () => {
  const modalEl = document.getElementById("submitModal");
  if (modalEl && window.bootstrap) {
    const modal = new bootstrap.Modal(modalEl);
    document.querySelectorAll("form.js-scan-form").forEach(f => {
      f.addEventListener("submit", () => modal.show());
    });
  }

  // 2) Rule-glossary popovers on the results page. Content lives in hidden
  //    #pop-<rule_id> blocks; each trigger references one by id.
  if (window.bootstrap) {
    document.querySelectorAll('[data-bs-toggle="popover"]').forEach(el => {
      const ref = el.getAttribute("data-bs-content-ref");
      const node = ref && document.getElementById(ref);
      new bootstrap.Popover(el, {
        html: true,
        sanitize: false,
        trigger: "focus",
        placement: "left",
        container: "body",
        content: () => (node ? node.innerHTML : ""),
      });
    });
  }

  // 3) File-tree switching on results page
  const links = document.querySelectorAll(".file-link");
  if (links.length) {
    links.forEach(a => {
      a.addEventListener("click", e => {
        e.preventDefault();
        links.forEach(x => x.classList.remove("active"));
        a.classList.add("active");
        document.querySelectorAll(".file-panel").forEach(p => p.classList.add("d-none"));
        const tgt = document.getElementById(a.dataset.target);
        if (tgt) tgt.classList.remove("d-none");
      });
    });
  }

  // 4) File-tree sort toggle: A–Z <-> offending files first. Reorders only the
  //    per-file anchors (those with data-path); the "All findings" link, which
  //    has no data-path, stays pinned at the top. Panels match by id, so a pure
  //    DOM reorder is safe.
  const sortBtn = document.getElementById("filetree-sort");
  const tree = document.querySelector(".file-tree");
  if (sortBtn && tree) {
    sortBtn.addEventListener("click", () => {
      const mode = sortBtn.dataset.mode === "alpha" ? "issues" : "alpha";
      sortBtn.dataset.mode = mode;
      sortBtn.textContent = mode === "alpha" ? "A–Z" : "Issues first";
      const items = Array.from(tree.querySelectorAll(".file-link[data-path]"));
      items.sort((a, b) => {
        const pa = a.dataset.path, pb = b.dataset.path;
        if (mode === "issues") {
          const d = (+b.dataset.findings) - (+a.dataset.findings);
          if (d !== 0) return d;
        }
        return pa.localeCompare(pb);
      });
      items.forEach(el => tree.appendChild(el));
    });
  }
});
