// No framework, no build step. Wires up: the asset graph's click-to-inspect
// panel, sidebar collapse, Azure/Lavender theme toggle, export dropdown, "/"
// search shortcut, and a scan-progress overlay shown while the pipeline
// form submits (a real network request underneath — this is honest loading
// feedback, not a simulated progress bar pretending to track real work).
document.addEventListener("DOMContentLoaded", function () {
  // ---- sidebar collapse ----
  var sidebar = document.getElementById("sidebar");
  var sidebarToggle = document.getElementById("sidebar-toggle");
  if (sidebar && sidebarToggle) {
    if (localStorage.getItem("tm_sidebar_collapsed") === "1") {
      sidebar.classList.add("collapsed");
      sidebarToggle.innerHTML = "&#10095;";
    }
    sidebarToggle.addEventListener("click", function () {
      var collapsed = sidebar.classList.toggle("collapsed");
      localStorage.setItem("tm_sidebar_collapsed", collapsed ? "1" : "0");
      sidebarToggle.innerHTML = collapsed ? "&#10095;" : "&#10094;";
    });
  }

  // ---- Azure / Lavender theme toggle (both themes are light) ----
  var themeToggle = document.getElementById("theme-toggle");
  var themeIcon = document.getElementById("theme-icon");
  var AZURE_ICON = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="8.5" fill="#2563EB" fill-opacity="0.15" stroke="#2563EB" stroke-width="1.6"/><circle cx="12" cy="12" r="3.2" fill="#2563EB"/></svg>';
  var LAVENDER_ICON = '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><circle cx="12" cy="12" r="8.5" fill="#7C3AED" fill-opacity="0.15" stroke="#7C3AED" stroke-width="1.6"/><circle cx="12" cy="12" r="3.2" fill="#7C3AED"/></svg>';

  function syncThemeIcon() {
    var current = document.documentElement.getAttribute("data-theme") || "azure";
    if (themeIcon) themeIcon.innerHTML = current === "lavender" ? LAVENDER_ICON : AZURE_ICON;
    if (themeToggle) themeToggle.title = current === "lavender" ? "Switch to Azure theme" : "Switch to Lavender theme";
  }
  syncThemeIcon();
  if (themeToggle) {
    themeToggle.addEventListener("click", function () {
      var current = document.documentElement.getAttribute("data-theme") || "azure";
      var next = current === "lavender" ? "azure" : "lavender";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("tm_theme", next);
      syncThemeIcon();
    });
  }

  // ---- export + profile dropdowns ----
  [["export-toggle", "export-dropdown"], ["profile-toggle", "profile-dropdown"]].forEach(function (pair) {
    var toggle = document.getElementById(pair[0]);
    var dropdown = document.getElementById(pair[1]);
    if (toggle && dropdown) {
      toggle.addEventListener("click", function (e) {
        e.stopPropagation();
        dropdown.classList.toggle("open");
      });
      document.addEventListener("click", function () {
        dropdown.classList.remove("open");
      });
    }
  });

  // ---- "/" focuses global search (lightweight nod to a command palette) ----
  var searchInput = document.getElementById("global-search");
  document.addEventListener("keydown", function (e) {
    if (e.key === "/" && document.activeElement !== searchInput && !["INPUT", "TEXTAREA"].includes(document.activeElement.tagName)) {
      e.preventDefault();
      if (searchInput) searchInput.focus();
    }
  });

  // ---- scan-progress overlay while the pipeline runs ----
  var overlay = document.getElementById("scan-overlay");
  document.querySelectorAll("form[action*='run-pipeline'], form[action*='analyze-']").forEach(function (form) {
    form.addEventListener("submit", function () {
      if (overlay) overlay.classList.add("active");
    });
  });

  // ---- drag-and-drop upload areas ----
  document.querySelectorAll(".dropzone").forEach(function (zone) {
    var input = zone.querySelector(".dropzone-input");
    var emptyState = zone.querySelector(".dropzone-empty");
    var fileState = zone.querySelector(".dropzone-file");
    if (!input) return;

    function formatSize(bytes) {
      if (bytes < 1024) return bytes + " B";
      if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
      return (bytes / (1024 * 1024)).toFixed(2) + " MB";
    }

    function showSelectedFile() {
      if (!input.files || !input.files.length) return;
      var file = input.files[0];
      var nameEl = fileState.querySelector(".dropzone-file-name");
      var metaEl = fileState.querySelector(".dropzone-file-meta");
      if (nameEl) nameEl.textContent = file.name;
      if (metaEl) metaEl.textContent = formatSize(file.size);
      if (emptyState) emptyState.style.display = "none";
      fileState.classList.add("visible");
    }

    function resetZone() {
      input.value = "";
      if (emptyState) emptyState.style.display = "";
      fileState.classList.remove("visible");
    }

    zone.addEventListener("click", function (e) {
      if (e.target.closest(".dropzone-remove")) return;
      input.click();
    });
    zone.addEventListener("keydown", function (e) {
      if (e.key === "Enter" || e.key === " ") { e.preventDefault(); input.click(); }
    });
    zone.addEventListener("dragover", function (e) { e.preventDefault(); zone.classList.add("dragover"); });
    zone.addEventListener("dragleave", function () { zone.classList.remove("dragover"); });
    zone.addEventListener("drop", function (e) {
      e.preventDefault();
      zone.classList.remove("dragover");
      if (e.dataTransfer.files && e.dataTransfer.files.length) {
        input.files = e.dataTransfer.files;
        showSelectedFile();
      }
    });
    input.addEventListener("change", showSelectedFile);

    var removeBtn = zone.querySelector(".dropzone-remove");
    if (removeBtn) {
      removeBtn.addEventListener("click", function (e) {
        e.stopPropagation();
        resetZone();
      });
    }
  });

  // ---- "Fit to View" — resets scroll position. Wired independently of the
  // node-inspector code below, so it works even if the graph SVG itself
  // failed to render for any reason ----
  var graphPanel = document.getElementById("graph-panel");
  var fitBtn = document.getElementById("graph-fit-btn");
  if (fitBtn && graphPanel) {
    fitBtn.addEventListener("click", function () {
      graphPanel.scrollTo({ top: 0, left: 0, behavior: "smooth" });
    });
  }

  var graph = document.getElementById("asset-graph");
  if (!graph) return;

  var metaEl = document.getElementById("asset-node-meta");
  var nodeMeta = metaEl ? JSON.parse(metaEl.textContent) : {};

  var threatsEl = document.getElementById("threats-data");
  var threats = threatsEl ? JSON.parse(threatsEl.textContent) : [];

  var inspector = document.getElementById("inspector-content");

  graph.querySelectorAll(".asset-node").forEach(function (node) {
    node.addEventListener("click", function () {
      var id = node.getAttribute("data-asset-id");
      var asset = nodeMeta[id];
      if (!asset || !inspector) return;

      var related = threats.filter(function (t) {
        return t.affected_asset === asset.name;
      });

      var html = "";
      html += '<div style="display:flex;align-items:center;gap:10px;padding-bottom:12px;border-bottom:1px solid var(--border);margin-bottom:12px;">';
      html += '<div style="width:40px;height:40px;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#fff;font-size:11px;font-weight:700;background:' + colorFor(asset.type) + ';">' + initials(asset.name) + '</div>';
      html += '<div><div style="font-weight:600;font-size:13px;">' + escapeHtml(asset.name) + '</div><div style="font-size:11px;color:var(--navy-500);">' + escapeHtml(asset.type) + '</div></div>';
      html += '</div>';

      html += '<div style="font-size:12px;margin-bottom:12px;">';
      html += row("Technology", asset.technology || "-");
      html += row("Criticality", asset.criticality || "-");
      html += row("Connections", (asset.connections || []).length);
      html += '</div>';

      html += '<div style="font-size:11px;text-transform:uppercase;letter-spacing:.03em;color:var(--navy-600);font-weight:600;margin-bottom:8px;">Related threats (' + related.length + ')</div>';
      if (related.length === 0) {
        html += '<p style="font-size:12px;color:var(--navy-500);">No threats mapped to this asset yet.</p>';
      } else {
        related.forEach(function (t) {
          html += '<a class="related-threat-card" href="/threats/' + t.id + '">';
          html += '<div style="display:flex;justify-content:space-between;align-items:center;">';
          html += '<span class="badge badge-stride-' + strideInitial(t.stride_category) + '">' + strideInitial(t.stride_category) + '</span>';
          html += '<span class="badge badge-risk risk-' + (t.risk_level || "Informational") + '">' + (t.risk_level || "Informational") + '</span>';
          html += '</div>';
          html += '<div style="font-size:12px;margin-top:4px;">' + escapeHtml(t.title) + '</div>';
          html += '</a>';
        });
      }

      inspector.innerHTML = html;
    });
  });

  function row(label, value) {
    return '<div style="display:flex;justify-content:space-between;padding:3px 0;"><span style="color:var(--navy-500);">' + label + '</span><span style="font-weight:500;">' + escapeHtml(String(value)) + '</span></div>';
  }
  function initials(name) {
    return name.split(/\s+/).map(function (w) { return w[0]; }).join("").slice(0, 3).toUpperCase();
  }
  function colorFor(type) {
    var colors = {
      "Web Application": "#2563eb", "API": "#3b82f6", "Authentication Service": "#0d9488",
      "Database": "#c0293c", "Payment Service": "#b45309", "External API": "#7c3aed",
      "Cloud Service": "#0891b2", "Monitoring Service": "#65a30d", "Storage": "#64748b",
      "User": "#94a3b8", "Admin": "#334155"
    };
    return colors[type] || "#94a3b8";
  }
  function strideInitial(category) {
    var map = { "Spoofing": "S", "Tampering": "T", "Repudiation": "R", "Information Disclosure": "I", "Denial of Service": "D", "Elevation of Privilege": "E" };
    return map[category] || "?";
  }
  function escapeHtml(s) {
    return String(s).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c];
    });
  }
});
