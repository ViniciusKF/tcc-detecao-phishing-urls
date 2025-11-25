from __future__ import annotations
from fastapi import FastAPI, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, validator
from typing import List, Dict, Tuple, Optional
import os, time, csv, json
from pathlib import Path
import numpy as np
from joblib import load
from features import extract_features, vectorize_features, FEATURE_ORDER, FEATURE_LABELS

APP_VERSION = "0.5.0 (ML-optional + logs/metrics/bulk + security)"

# ---------- Config via env ----------
MODEL_PATH   = os.environ.get("PHISHGUARD_MODEL", "models/phishguard_lr.joblib")
CORS_ORIGINS = os.environ.get("PHISHGUARD_CORS", "http://localhost:3000,http://localhost:3001")
THRESHOLD    = float(os.environ.get("PHISHGUARD_THRESHOLD", "0.6"))
LOG_PATH     = os.environ.get("PHISHGUARD_LOG", "logs/predictions.csv")

# ---------- App ----------
app = FastAPI(
    title="Detector API",
    version=APP_VERSION,
    description="API de detecção de phishing com Machine Learning e interpretabilidade"
)

# ========== CORREÇÃO: CORS RESTRITIVO ==========
# Configuração segura de CORS (não permite "*")
if CORS_ORIGINS == "*":
    print("[WARNING] CORS configurado como '*' (inseguro). Configure PHISHGUARD_CORS com origens específicas.")
    allow_origins = ["*"]
else:
    allow_origins = [o.strip() for o in CORS_ORIGINS.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allow_origins,
    allow_credentials=False,  # Não permite credenciais com "*"
    allow_methods=["GET", "POST"],  # Apenas métodos necessários
    allow_headers=["Content-Type", "Authorization"],  # Headers específicos
)

print(f"[PhishGuard] CORS configurado para: {allow_origins}")

# ---------- Modelo ML ----------
USE_ML = False
PIPE = None
MODEL_META: Dict[str, Optional[str]] = {"version": None, "trained_at": None}

def _init_model():
    """
    Inicializa o modelo ML e carrega o limiar calibrado.
    
    CORREÇÃO: Agora carrega o limiar calibrado de threshold.json se disponível.
    """
    global USE_ML, PIPE, THRESHOLD, MODEL_META
    
    try:
        # Carregar modelo
        payload = load(MODEL_PATH)
        PIPE = payload["pipeline"]
        
        # Carregar limiar do modelo (se disponível)
        model_threshold = float(payload.get("threshold", THRESHOLD))
        
        # Tentar carregar limiar calibrado de threshold.json
        threshold_file = Path(MODEL_PATH).parent / "threshold.json"
        if threshold_file.exists():
            with open(threshold_file, 'r') as f:
                threshold_config = json.load(f)
                calibrated_threshold = threshold_config.get('optimal_threshold', model_threshold)
                THRESHOLD = calibrated_threshold
                print(f"[PhishGuard] ✅ Limiar calibrado carregado: {THRESHOLD:.4f}")
        else:
            THRESHOLD = model_threshold
            print(f"[PhishGuard] ⚠️  threshold.json não encontrado. Usando limiar do modelo: {THRESHOLD:.4f}")
        
        MODEL_META["version"]   = str(payload.get("version"))
        MODEL_META["trained_at"]= str(payload.get("trained_at"))
        USE_ML = True
        print(f"[PhishGuard] ✅ Modelo carregado: {MODEL_PATH}")
        
    except Exception as e:
        print(f"[PhishGuard] ⚠️  Sem modelo ML (usando heurística). Detalhe: {e}")
        USE_ML = False

_init_model()

# ---------- Heurística (fallback) ----------
def heuristic_score(f: dict) -> Tuple[float, List[str]]:
    """
    Calcula score de risco baseado em regras heurísticas.
    Usado como fallback quando modelo ML não está disponível.
    """
    score = 0.0
    reasons: List[str] = []
    
    def add(p: float, why: str):
        nonlocal score
        score += p
        reasons.append(why)
    
    # Regras heurísticas
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
                                       add(0.10, "'https' na URL mas conexão não é HTTPS")
    if f["num_params"] >= 4:           add(0.08, "Parâmetros demais no query string")
    if f["very_long_url"]:             add(0.10, "URL muito longa (>100)")
    elif f["len_url"] > 80:            add(0.06, "URL longa (>80)")
    if f["num_digits"] >= 8:           add(0.06, "Muitos dígitos na URL")
    if f["num_special"] >= 3:          add(0.05, "Muitos caracteres especiais")
    
    risk = max(0.0, min(1.0, score))
    return risk, reasons[:5]

# ---------- Util: logging ----------
def log_event(url: str, risk: float, label: str, mode: str):
    """
    Registra predição em arquivo CSV para análise posterior.
    
    NOTA: Em produção, considere sanitizar URLs antes de logar
    para evitar vazamento de informações sensíveis.
    """
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        new_file = not os.path.exists(LOG_PATH)
        
        with open(LOG_PATH, "a", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            if new_file:
                w.writerow(["ts","url","risk","label","mode","version"])
            
            # MELHORIA: Truncar URL muito longa para evitar problemas de log
            url_truncated = url[:500] if len(url) > 500 else url
            w.writerow([
                time.strftime("%Y-%m-%d %H:%M:%S"),
                url_truncated,
                f"{risk:.6f}",
                label,
                mode,
                APP_VERSION
            ])
    except Exception as e:
        print(f"[PhishGuard] Erro ao logar evento: {e}")

# ---------- Schemas ----------
class URLRequest(BaseModel):
    """Schema para requisição de predição de URL."""
    url: str
    
    @validator('url')
    def validate_url(cls, v):
        """
        CORREÇÃO: Validação de URL para prevenir injeção.
        """
        if not v:
            raise ValueError('URL não pode ser vazia')
        
        if len(v) > 2048:
            raise ValueError('URL muito longa (máximo 2048 caracteres)')
        
        if not v.startswith(('http://', 'https://')):
            raise ValueError('URL deve começar com http:// ou https://')
        
        return v

class Contribution(BaseModel):
    feature: str
    contribution: Optional[float]

class Prediction(BaseModel):
    url: str
    risk: float
    label: str
    reasons: List[str]
    features: Dict[str, float]
    mode: str  # "ml" | "heuristic"
    threshold: float  # Limiar usado na predição
    confidence: str  # "high" | "medium" | "low"

class Explanation(BaseModel):
    url: str
    risk: float
    label: str
    top_contributions: List[Contribution]
    feature_order: List[str]
    mode: str
    threshold: float

class BulkRequest(BaseModel):
    urls: List[str]
    
    @validator('urls')
    def validate_urls(cls, v):
        if len(v) > 100:
            raise ValueError('Máximo de 100 URLs por requisição')
        return v

class BulkItem(BaseModel):
    url: str
    risk: float
    label: str
    mode: str

class BulkResponse(BaseModel):
    items: List[BulkItem]
    count: int

# ---------- ML predict ----------
def predict_ml(fmap: Dict[str, float]) -> Tuple[float, List[str]]:
    """
    Realiza predição usando modelo de Machine Learning.
    Retorna score de risco e razões (top 5 features mais importantes).
    """
    x = np.asarray([vectorize_features(fmap)], dtype=float)
    risk = float(PIPE.predict_proba(x)[0,1])
    reasons: List[str] = []
    
    try:
        scaler = PIPE.named_steps.get("scaler", None)
        model = PIPE.named_steps.get("model", None)
        
        if scaler is not None and model is not None and hasattr(model, "coef_"):
            x_scaled = scaler.transform(x).astype(float)[0]
            coefs = np.asarray(model.coef_[0], dtype=float)
            contribs = coefs * x_scaled
            
            # Top 5 features mais importantes
            idxs = np.argsort(np.abs(contribs))[::-1][:5]
            for i in idxs:
                label = FEATURE_LABELS.get(FEATURE_ORDER[i], FEATURE_ORDER[i])
                reasons.append(f"{label} (contrib={float(contribs[i]):+.2f})")
    except Exception:
        reasons = ["Modelo ML aplicado", "Contribuições indisponíveis", "Verifique pipeline"]
    
    return risk, reasons

# ---------- Endpoints ----------
@app.get("/health")
def health():
    """Verifica status da API e configuração."""
    return {
        "ok": True,
        "mode": ("ml" if USE_ML else "heuristic"),
        "threshold": THRESHOLD,
        "version": APP_VERSION,
        "model_meta": MODEL_META,
    }

@app.get("/version")
def version():
    """Retorna versão da API e modo de operação."""
    return {
        "version": APP_VERSION,
        "mode": ("ml" if USE_ML else "heuristic"),
        "model_meta": MODEL_META
    }

@app.get("/metrics")
def metrics():
    """Retorna métricas de uso da API (total de predições por label)."""
    total = 0
    by_label = {"legitima": 0, "indefinida": 0, "suspeita": 0}
    
    try:
        if os.path.exists(LOG_PATH):
            with open(LOG_PATH, "r", encoding="utf-8") as f:
                r = csv.DictReader(f)
                for row in r:
                    total += 1
                    lbl = row.get("label", "")
                    if lbl in by_label:
                        by_label[lbl] += 1
    except Exception:
        pass
    
    return {
        "total": total,
        "by_label": by_label,
        "mode": ("ml" if USE_ML else "heuristic"),
        "threshold": THRESHOLD,
        "version": APP_VERSION,
        "model_meta": MODEL_META,
        "log_path": LOG_PATH,
    }

@app.get("/predict", response_model=Prediction)
def predict(url: str = Query(..., description="URL a ser verificada")):
    """
    Prediz se uma URL é phishing ou legítima.
    
    CORREÇÃO: Agora retorna também o limiar usado e nível de confiança.
    """
    # Validar URL manualmente (além da validação do Pydantic)
    if len(url) > 2048:
        return Prediction(
            url=url[:100] + "...",
            risk=0.0,
            label="erro",
            reasons=["URL muito longa (>2048 caracteres)"],
            features={},
            mode="error",
            threshold=THRESHOLD,
            confidence="low"
        )
    
    fmap = extract_features(url)
    
    if USE_ML:
        risk, reasons = predict_ml(fmap)
        label = "suspeita" if risk >= THRESHOLD else ("legitima" if risk < 0.4 else "indefinida")
        
        # Calcular nível de confiança
        distance_from_threshold = abs(risk - THRESHOLD)
        if distance_from_threshold > 0.3:
            confidence = "high"
        elif distance_from_threshold > 0.15:
            confidence = "medium"
        else:
            confidence = "low"
        
        log_event(url, risk, label, "ml")
        
        return Prediction(
            url=url,
            risk=round(risk, 3),
            label=label,
            reasons=reasons,
            features=fmap,
            mode="ml",
            threshold=THRESHOLD,
            confidence=confidence
        )
    else:
        risk, reasons = heuristic_score(fmap)
        label = "suspeita" if risk >= 0.6 else ("legitima" if risk < 0.4 else "indefinida")
        
        distance_from_threshold = abs(risk - 0.6)
        confidence = "high" if distance_from_threshold > 0.2 else "medium"
        
        log_event(url, risk, label, "heuristic")
        
        return Prediction(
            url=url,
            risk=round(risk, 3),
            label=label,
            reasons=reasons,
            features=fmap,
            mode="heuristic",
            threshold=0.6,
            confidence=confidence
        )

@app.get("/predict_explain", response_model=Explanation)
def predict_explain(url: str = Query(..., description="URL a ser explicada")):
    """
    Prediz e explica a decisão do modelo (top 8 features mais importantes).
    """
    fmap = extract_features(url)
    
    try:
        if USE_ML:
            x = np.asarray([vectorize_features(fmap)], dtype=float)
            risk = float(PIPE.predict_proba(x)[0,1])
            label = "suspeita" if risk >= THRESHOLD else ("legitima" if risk < 0.4 else "indefinida")
            
            top: List[Contribution] = []
            scaler = PIPE.named_steps.get("scaler", None)
            model = PIPE.named_steps.get("model", None)
            
            if scaler is not None and model is not None and hasattr(model, "coef_"):
                x_scaled = scaler.transform(x).astype(float)[0]
                coefs = np.asarray(model.coef_[0], dtype=float)
                contribs = coefs * x_scaled
                
                # Top 8 features mais importantes
                idxs = np.argsort(np.abs(contribs))[::-1][:8]
                for i in idxs:
                    top.append(Contribution(
                        feature=FEATURE_ORDER[i],
                        contribution=float(contribs[i])
                    ))
            
            return Explanation(
                url=url,
                risk=round(risk, 3),
                label=label,
                top_contributions=top,
                feature_order=FEATURE_ORDER,
                mode="ml",
                threshold=THRESHOLD
            )
        else:
            risk, reasons = heuristic_score(fmap)
            label = "suspeita" if risk >= 0.6 else ("legitima" if risk < 0.4 else "indefinida")
            top = [Contribution(feature=r, contribution=0.0) for r in reasons]
            
            return Explanation(
                url=url,
                risk=round(risk, 3),
                label=label,
                top_contributions=top,
                feature_order=FEATURE_ORDER,
                mode="heuristic",
                threshold=0.6
            )
    except Exception as e:
        # Fallback para heurística em caso de erro
        print(f"[PhishGuard] Erro em predict_explain: {e}")
        risk, reasons = heuristic_score(fmap)
        label = "suspeita" if risk >= 0.6 else ("legitima" if risk < 0.4 else "indefinida")
        top = [Contribution(feature=r, contribution=0.0) for r in reasons]
        
        return Explanation(
            url=url,
            risk=round(risk, 3),
            label=label,
            top_contributions=top,
            feature_order=FEATURE_ORDER,
            mode=("ml" if USE_ML else "heuristic"),
            threshold=THRESHOLD if USE_ML else 0.6
        )

@app.post("/predict_bulk", response_model=BulkResponse)
def predict_bulk(req: BulkRequest):
    """
    Prediz múltiplas URLs em lote (máximo 100 por requisição).
    """
    items: List[BulkItem] = []
    
    for u in req.urls:
        try:
            fmap = extract_features(u)
            
            if USE_ML:
                risk, _ = predict_ml(fmap)
                label = "suspeita" if risk >= THRESHOLD else ("legitima" if risk < 0.4 else "indefinida")
                log_event(u, risk, label, "ml")
                items.append(BulkItem(url=u, risk=round(risk, 3), label=label, mode="ml"))
            else:
                risk, _ = heuristic_score(fmap)
                label = "suspeita" if risk >= 0.6 else ("legitima" if risk < 0.4 else "indefinida")
                log_event(u, risk, label, "heuristic")
                items.append(BulkItem(url=u, risk=round(risk, 3), label=label, mode="heuristic"))
        except Exception as e:
            print(f"[PhishGuard] Erro ao processar URL {u}: {e}")
            items.append(BulkItem(url=u, risk=0.0, label="erro", mode="error"))
    
    return BulkResponse(items=items, count=len(items))

# ---------- Startup ----------
@app.on_event("startup")
async def startup_event():
    """Evento executado ao iniciar a API."""
    print("\n" + "="*60)
    print("PHISHGUARD API INICIADA")
    print("="*60)
    print(f"Versão: {APP_VERSION}")
    print(f"Modo: {'Machine Learning' if USE_ML else 'Heurística'}")
    print(f"Limiar: {THRESHOLD:.4f}")
    print(f"CORS: {allow_origins}")
    print(f"Modelo: {MODEL_PATH}")
    print("="*60 + "\n")
