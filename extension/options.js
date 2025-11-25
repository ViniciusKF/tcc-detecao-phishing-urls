console.log("[PhishGuard] options.js loaded");
document.addEventListener("DOMContentLoaded", () => {
  const DEFAULTS = { API_BASE: "http://localhost:8000", THRESHOLD: 0.6 };
  const $ = (id) => document.getElementById(id);

  chrome.storage.sync.get(DEFAULTS, (cfg) => {
    $("apiBase").value = cfg.API_BASE;
    $("threshold").value = cfg.THRESHOLD;
  });

  $("save").addEventListener("click", () => {
    const API_BASE = $("apiBase").value.trim() || DEFAULTS.API_BASE;
    let THRESHOLD = parseFloat($("threshold").value);
    if (isNaN(THRESHOLD) || THRESHOLD < 0 || THRESHOLD > 1) THRESHOLD = DEFAULTS.THRESHOLD;

    chrome.storage.sync.set({ API_BASE, THRESHOLD }, () => {
      const msg = $("msg");
      msg.textContent = "Salvo!";
      setTimeout(() => (msg.textContent = ""), 1200);
    });
  });
});

