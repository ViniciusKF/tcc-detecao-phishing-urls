(function(){
  console.debug("[PhishGuard] content.js start on", location.href);
  const DEFAULTS = { API_BASE: "http://localhost:8000", THRESHOLD: 0.6 };
  const getConfig = () => new Promise(res => chrome.storage.sync.get(DEFAULTS, res));

  async function check(){
    try {
      const cfg = await getConfig();
      const msg = await chrome.runtime.sendMessage({ type: "predict", url: location.href });
      if (!msg?.ok) throw new Error(msg?.error || "bg fetch failed");
      const data = msg.data;
      if (typeof data.risk === "number" && data.risk >= cfg.THRESHOLD) injectBanner(data);
    } catch (e) {
      console.error("[PhishGuard] predict error", e);
    }
  }

  function injectBanner(data){
    if (document.getElementById("phishguard-banner")) return;

    const banner = document.createElement("div");
    Object.assign(banner.style, {
      position:"fixed", top:0, left:0, right:0, zIndex:2147483647,
      background:"#ef4444", color:"#0b1220", padding:"12px 16px",
      display:"flex", alignItems:"center", justifyContent:"space-between",
      boxShadow:"0 2px 10px rgba(0,0,0,.25)", fontFamily:"system-ui,-apple-system,Segoe UI,Roboto,Arial",
    });
    banner.id = "phishguard-banner";

    // ========== CORREÇÃO: Usar textContent em vez de innerHTML ==========
    // Previne XSS caso data.reasons contenha código malicioso
    const left = document.createElement("div");
    
    // Criar elementos de forma segura
    const strong = document.createElement("strong");
    strong.textContent = "⚠️ Possível phishing";
    
    const riskText = document.createTextNode(` — Risco ${(data.risk*100).toFixed(0)}%. `);
    
    const reasonsSpan = document.createElement("span");
    reasonsSpan.style.opacity = "0.85";
    reasonsSpan.textContent = `Motivos: ${data.reasons?.join("; ") || "padrões suspeitos"}`;
    
    left.appendChild(strong);
    left.appendChild(riskText);
    left.appendChild(reasonsSpan);

    const mkBtn = (t)=>{ 
      const b=document.createElement("button"); 
      b.textContent=t;  // textContent é seguro
      styleBtn(b); 
      return b; 
    };
    
    const exitBtn = mkBtn("Sair do site");
    const okBtn   = mkBtn("Prosseguir");
    okBtn.style.background = "#0b1220"; 
    okBtn.style.color = "#ef4444";

    // Vai para Google e não deixa o suspeito no histórico
    exitBtn.onclick = () => {
      try { 
        window.top.location.replace("https://www.google.com/"); 
      } catch(e) { 
        location.href = "https://www.google.com/"; 
      }
    };
    
    okBtn.onclick = () => { 
      banner.remove(); 
      const s=document.getElementById("phishguard-spacer"); 
      if(s) s.remove(); 
    };

    const right = document.createElement("div");
    right.append(exitBtn, okBtn);

    banner.append(left, right);
    document.documentElement.appendChild(banner);

    const spacer = document.createElement("div");
    Object.assign(spacer.style, { height:"56px", width:"100%", display:"block" });
    spacer.id = "phishguard-spacer";
    document.body.prepend(spacer);
  }

  function styleBtn(b){
    Object.assign(b.style, {
      border:"0", borderRadius:"999px", padding:"8px 12px",
      fontWeight:"700", cursor:"pointer", background:"#0b1220", color:"#fff", marginLeft:"8px",
    });
  }

  check();
})();
