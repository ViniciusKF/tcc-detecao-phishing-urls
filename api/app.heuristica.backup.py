# app.py
from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import re, urllib.parse

app = FastAPI(title="PhishGuard API", version="0.2.0")

# CORS liberado para testes (em produção, restrinja)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

SUSPECT_WORDS = [
    "login", "verify", "update", "secure", "account", "bank", "confirm",
    "password", "reset", "gift", "free", "promo", "win", "bonus",
]

class Prediction(BaseModel):
    url: str
    risk: float              # 0..1
    label: str               # "legitima" | "suspeita" | "indefinida"
    reasons: list[str]       # top motivos
    features: dict           # métricas brutas p/ depuração

def _is_ip(host: str) -> bool:
    return bool(re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host))

def _count_subdomains(host: str) -> int:
    parts = [p for p in host.split(".") if p]
    return max(0, len(parts) - 2)

def extract_features(url: str) -> dict:
    try:
        parsed = urllib.parse.urlparse(url if "://" in url else "http://" + url)
    except Exception:
        parsed = urllib.parse.urlparse("http://" + url)

    host = (parsed.netloc or "").lower()
    path_q = (parsed.path or "") + ("?" + parsed.query if parsed.query else "")
    full = (parsed.geturl() or url)
    scheme = parsed.scheme.lower()

    f = {}
    f["len_url"] = len(full)
    f["len_host"] = len(host)
    f["num_dots"] = host.count(".")
    f["num_hyphens"] = full.count("-")
    f["num_at"] = full.count("@")
    f["num_digits"] = sum(c.isdigit() for c in full)
    f["num_params"] = parsed.query.count("=")
    f["num_special"] = sum(c in "#?%&" for c in full)
    f["has_ip_host"] = int(_is_ip(host))
    f["uses_https"] = int(scheme == "https")
    f["scheme_is_http"] = int(scheme == "http")
    f["https_in_path"] = int("https" in path_q.lower())
    f["many_subdomains"] = int(_count_subdomains(host) >= 3)
    f["suspicious_words"] = sum(w in full.lower() for w in SUSPECT_WORDS)
    f["host_has_suspicious"] = sum(w in host for w in SUSPECT_WORDS)
    f["has_long_path"] = int(len(path_q) > 60)
    f["very_long_url"] = int(len(full) > 100)
    f["auth_terms_http"] = int(
        scheme == "http" and any(w in (host + path_q) for w in ["login", "verify", "account", "secure"])
    )
    return f

def heuristic_score(f: dict) -> tuple[float, list[str]]:
    score = 0.0
    reasons: list[str] = []

    def add(p: float, why: str):
        nonlocal score; score += p; reasons.append(why)

    if f["scheme_is_http"]:            add(0.12, "Conexão HTTP sem HTTPS")
    if f["suspicious_words"] >= 4:     add(0.25, "Várias palavras sensíveis na URL")
    elif f["suspicious_words"] >= 2:   add(0.18, "Palavras sensíveis na URL")
    elif f["suspicious_words"] >= 1:   add(0.10, "Palavra sensível na URL")
    if f["host_has_suspicious"] >= 1:  add(0.15, "Palavra sensível no host")
    if f["num_hyphens"] >= 2:          add(0.10, "Muitos hífens na URL")
    if f["many_subdomains"]:           add(0.10, "Excesso de subdomínios")
    if f["auth_terms_http"]:           add(0.10, "HTTP + termos de autenticação")

    if f["has_ip_host"]:               add(0.12, "Host é um endereço IP")
    if f["https_in_path"] and not f["uses_https"]:
                                       add(0.10, "‘https’ na URL mas conexão não é HTTPS")
    if f["num_params"] >= 4:           add(0.08, "Parâmetros demais no query string")
    if f["very_long_url"]:             add(0.10, "URL muito longa (>100)")
    elif f["len_url"] > 80:            add(0.06, "URL longa (>80)")
    if f["num_digits"] >= 8:           add(0.06, "Muitos dígitos na URL")
    if f["num_special"] >= 3:          add(0.05, "Muitos caracteres especiais")

    risk = max(0.0, min(1.0, score))
    return risk, reasons[:5]

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/predict", response_model=Prediction)
def predict(url: str = Query(..., description="URL a ser verificada")):
    f = extract_features(url)
    risk, reasons = heuristic_score(f)
    label = "suspeita" if risk >= 0.6 else ("legitima" if risk < 0.4 else "indefinida")
    return Prediction(url=url, risk=round(risk, 3), label=label, reasons=reasons, features=f)
