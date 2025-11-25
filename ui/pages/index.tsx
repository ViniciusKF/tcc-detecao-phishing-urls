import { useMemo, useState } from "react";

type Label = "legitima" | "suspeita" | "indefinida";

type ApiResp = {
  url: string;
  risk: number;
  label: Label;
  reasons: string[];
  features: Record<string, number>;
  mode?: string;
};

type ExplResp = {
  url: string;
  risk: number;
  label: Label;
  top_contributions: { feature: string; contribution: number | null }[];
  feature_order: string[];
  mode: string;
};

const FEAT_LABELS: Record<string, string> = {
  len_url: "URL longa",
  len_host: "Host longo",
  num_dots: "Muitos pontos no host",
  num_hyphens: "Muitos hífens",
  num_at: "Símbolo @ na URL",
  num_digits: "Muitos dígitos",
  num_params: "Parâmetros no query",
  num_special: "Muitos especiais",
  has_ip_host: "Host é IP",
  uses_https: "Conexão HTTPS",
  scheme_is_http: "Conexão HTTP (sem HTTPS)",
  https_in_path: "‘https’ no caminho",
  many_subdomains: "Excesso de subdomínios",
  suspicious_words: "Palavras sensíveis na URL",
  host_has_suspicious: "Palavras sensíveis no host",
  has_long_path: "Caminho longo",
  very_long_url: "URL muito longa",
  auth_terms_http: "HTTP + termos de autenticação",
};

export default function Home() {
  const [apiBase, setApiBase] = useState("http://localhost:8000");
  const [url, setUrl] = useState("");
  const [threshold, setThreshold] = useState(0.6);
  const [data, setData] = useState<ApiResp | null>(null);
  const [expl, setExpl] = useState<ExplResp | null>(null);
  const [loading, setLoading] = useState(false);

  const riskColor = data
    ? data.risk >= threshold
      ? "#ef4444"
      : data.risk < 0.4
      ? "#22c55e"
      : "#f59e0b"
    : "#64748b";

  const contribs = useMemo(() => {
    if (!expl?.top_contributions?.length) return [];
    return [...expl.top_contributions]
      .filter(c => typeof c.contribution === "number")
      .sort((a, b) => Math.abs((b.contribution ?? 0)) - Math.abs((a.contribution ?? 0)));
  }, [expl]);

  const maxAbs = useMemo(() => {
    return contribs.reduce((m, c) => Math.max(m, Math.abs(c.contribution ?? 0)), 0) || 1;
  }, [contribs]);

  const checkUrl = async () => {
    if (!url.trim()) return;
    setLoading(true);
    setData(null);
    setExpl(null);
    try {
      const p = await fetch(`${apiBase}/predict?url=${encodeURIComponent(url)}`);
      const pj: ApiResp = await p.json();
      setData(pj);

      const e = await fetch(`${apiBase}/predict_explain?url=${encodeURIComponent(url)}`);
      const ej: ExplResp = await e.json();
      setExpl(ej);
    } catch (err) {
      alert("Falha ao consultar a API. Verifique se ela está rodando em " + apiBase);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ minHeight: "100vh", background: "#0b1220", color: "#e5e7eb" }}>
      <div style={{ maxWidth: 920, margin: "0 auto", padding: "48px 16px" }}>
        <h1 style={{ fontSize: 28, marginBottom: 8 }}>Verificador de URL com Explicações</h1>
        <p style={{ opacity: 0.85, marginBottom: 24 }}>
          Digite uma URL. A API retorna o risco e as principais contribuições das features (ML/Heurística).
        </p>

        <label style={{ fontSize: 12, opacity: 0.8 }}>API base</label>
        <input
          value={apiBase}
          onChange={(e) => setApiBase(e.target.value)}
          style={{
            width: "100%", marginTop: 6, marginBottom: 16, padding: "10px 14px",
            borderRadius: 8, border: "1px solid #334155", background: "#0f172a", color: "#e5e7eb"
          }}
        />

        <div style={{ display: "grid", gridTemplateColumns: "1fr auto", gap: 12, marginBottom: 12 }}>
          <input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://exemplo.com/login"
            style={{
              width: "100%", padding: "12px 14px", borderRadius: 10,
              border: "1px solid #334155", background: "#0f172a", color: "#e5e7eb"
            }}
          />
          <button
            onClick={checkUrl}
            disabled={loading}
            style={{
              padding: "12px 16px", borderRadius: 10, background: "#3b82f6",
              border: "none", color: "#fff", cursor: "pointer", opacity: loading ? 0.6 : 1
            }}
          >
            {loading ? "Verificando..." : "Verificar + Explicar"}
          </button>
        </div>

        <div style={{ marginBottom: 20 }}>
          <label style={{ fontSize: 12, opacity: 0.8 }}>Limiar de alerta (0–1)</label>
          <input
            type="number" step="0.05" min="0" max="1" value={threshold}
            onChange={(e) => setThreshold(Number(e.target.value))}
            style={{
              width: 120, marginLeft: 10, padding: "8px 10px", borderRadius: 8,
              border: "1px solid #334155", background: "#0f172a", color: "#e5e7eb"
            }}
          />
        </div>

        {data && (
          <div style={{ border: "1px solid #1f2937", borderRadius: 14, padding: 20, background: "#0f172a", marginBottom: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 12 }}>
              <strong style={{ fontSize: 16 }}>{data.url}</strong>
              <span style={{ padding: "4px 10px", borderRadius: 999, background: riskColor, color: "#0b1220", fontWeight: 700 }}>
                {(data.risk * 100).toFixed(0)}%
              </span>
            </div>
            <p style={{ marginTop: 0, marginBottom: 8 }}>
              Classificação:{" "}
              <strong style={{ color: data.risk >= threshold ? "#ef4444" : data.risk < 0.4 ? "#22c55e" : "#f59e0b" }}>
                {data.label}
              </strong>{" "}
              <span style={{ opacity: 0.7, fontSize: 12 }}>({data.mode || "api"})</span>
            </p>
            {!!data.reasons?.length && (
              <>
                <p style={{ margin: "8px 0 6px" }}>Motivos (resumo):</p>
                <ul style={{ margin: 0, paddingLeft: 18 }}>
                  {data.reasons.map((r, i) => (
                    <li key={i} style={{ marginBottom: 4 }}>{r}</li>
                  ))}
                </ul>
              </>
            )}
            <details style={{ marginTop: 12 }}>
              <summary style={{ cursor: "pointer" }}>Ver features (brutas)</summary>
              <pre style={{ whiteSpace: "pre-wrap", background: "#0b1220", padding: 12, borderRadius: 8, border: "1px solid #1f2937" }}>
{JSON.stringify(data.features, null, 2)}
              </pre>
            </details>
          </div>
        )}

        {expl && (
          <div style={{ border: "1px solid #1f2937", borderRadius: 14, padding: 20, background: "#0f172a" }}>
            <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 8 }}>
              <strong>Explicações — Top contribuições ({expl.mode})</strong>
              <span style={{ opacity: 0.8 }}>{(expl.risk * 100).toFixed(0)}%</span>
            </div>
            {contribs.length ? (
              <ul style={{ margin: 0, padding: 0, listStyle: "none" }}>
                {contribs.map((c, i) => {
                  const label = FEAT_LABELS[c.feature] ?? c.feature;
                  const v = c.contribution ?? 0;
                  const frac = Math.min(1, Math.abs(v) / maxAbs);
                  return (
                    <li key={i} style={{ marginBottom: 8 }}>
                      <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
                        <div style={{ width: 220 }}>{label}</div>
                        <div style={{ flex: 1, height: 8, background: "#111827", borderRadius: 999 }}>
                          <div
                            style={{
                              width: `${(frac * 100).toFixed(0)}%`,
                              height: 8,
                              borderRadius: 999,
                              background: v >= 0 ? "#ef4444" : "#22c55e"
                            }}
                          />
                        </div>
                        <div style={{ width: 80, textAlign: "right", opacity: 0.9 }}>
                          {v >= 0 ? "+" : ""}{v.toFixed(2)}
                        </div>
                        <div style={{ width: 90, textAlign: "right", fontSize: 12, opacity: 0.7 }}>
                          {c.feature}
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p style={{ opacity: 0.8 }}>Sem contribuições disponíveis.</p>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
