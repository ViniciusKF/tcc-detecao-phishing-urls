chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (!msg || msg.type !== "predict") return;
  const DEFAULTS = { API_BASE: "http://localhost:8000" };
  chrome.storage.sync.get(DEFAULTS, async ({ API_BASE }) => {
    try {
      const r = await fetch(`${API_BASE}/predict?url=${encodeURIComponent(msg.url)}`, { credentials: "omit" });
      const data = await r.json();
      sendResponse({ ok: true, data });
    } catch (e) {
      sendResponse({ ok: false, error: String(e) });
    }
  });
  return true; // resposta assíncrona
});

