from __future__ import annotations
import argparse, json, os, time
import numpy as np
import pandas as pd
from joblib import dump
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    roc_auc_score, average_precision_score, classification_report,
    confusion_matrix, roc_curve, precision_recall_curve
)
import matplotlib.pyplot as plt

from features import extract_features, vectorize_features, FEATURE_ORDER

def load_dataset(csv_path: str) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    if not {"url","label"}.issubset(df.columns):
        raise ValueError("CSV must have columns: url,label")
    df["label"] = df["label"].astype(int)
    return df

def build_Xy(df: pd.DataFrame):
    feats = [extract_features(u) for u in df["url"].tolist()]
    X = np.array([vectorize_features(f) for f in feats], dtype=float)
    y = df["label"].values.astype(int)
    return X, y

def train_pipeline(X, y):
    pipe = Pipeline(steps=[
        ("scaler", StandardScaler()),
        ("model", LogisticRegression(max_iter=2000, class_weight="balanced", solver="liblinear")),
    ])
    pipe.fit(X, y)
    return pipe

def evaluate(pipe, X, y, threshold=0.5, tag="val"):
    """Avalia o modelo com métricas completas."""
    proba = pipe.predict_proba(X)[:,1]
    pred = (proba >= threshold).astype(int)
    
    acc = accuracy_score(y, pred)
    prec = precision_score(y, pred, zero_division=0)
    rec = recall_score(y, pred, zero_division=0)
    f1 = f1_score(y, pred, zero_division=0)
    
    try:
        auc_roc = roc_auc_score(y, proba)
        auc_pr = average_precision_score(y, proba)
    except Exception:
        auc_roc = float("nan")
        auc_pr = float("nan")
    
    cm = confusion_matrix(y, pred).tolist()
    
    return {
        "tag": tag,
        "threshold": threshold,
        "accuracy": acc,
        "precision": prec,
        "recall": rec,
        "f1_score": f1,
        "auc_roc": auc_roc,
        "auc_pr": auc_pr,
        "confusion_matrix": cm
    }

def calibrate_threshold(pipe, X_val, y_val):
    """
    Calibra o limiar de decisão para maximizar F1-Score.
    
    Returns:
        optimal_threshold (float): Limiar ótimo
        optimal_metrics (dict): Métricas com o limiar ótimo
    """
    print("\n" + "="*60)
    print("CALIBRAÇÃO DE LIMIAR DE DECISÃO")
    print("="*60)
    
    # Calcular probabilidades no conjunto de validação
    y_proba_val = pipe.predict_proba(X_val)[:, 1]
    
    # Calcular curva Precision-Recall
    precision, recall, thresholds = precision_recall_curve(y_val, y_proba_val)
    
    # Calcular F1-Score para cada limiar
    f1_scores = 2 * (precision * recall) / (precision + recall + 1e-10)
    
    # Encontrar limiar que maximiza F1-Score
    optimal_idx = np.argmax(f1_scores)
    optimal_threshold = thresholds[optimal_idx] if optimal_idx < len(thresholds) else 0.5
    optimal_f1 = f1_scores[optimal_idx]
    optimal_precision = precision[optimal_idx]
    optimal_recall = recall[optimal_idx]
    
    print(f"\n🎯 Limiar Ótimo Encontrado:")
    print(f"  Threshold: {optimal_threshold:.4f}")
    print(f"  F1-Score:  {optimal_f1:.4f}")
    print(f"  Precision: {optimal_precision:.4f}")
    print(f"  Recall:    {optimal_recall:.4f}")
    
    # Comparar com limiar padrão (0.5)
    y_pred_default = (y_proba_val > 0.5).astype(int)
    y_pred_optimal = (y_proba_val > optimal_threshold).astype(int)
    
    f1_default = f1_score(y_val, y_pred_default)
    f1_optimal_test = f1_score(y_val, y_pred_optimal)
    
    print(f"\n📊 Comparação de Limiares:")
    print(f"  Limiar 0.5000: F1 = {f1_default:.4f}")
    print(f"  Limiar {optimal_threshold:.4f}: F1 = {f1_optimal_test:.4f}")
    print(f"  Ganho: {(f1_optimal_test - f1_default)*100:+.2f}%")
    
    print("="*60 + "\n")
    
    return optimal_threshold, {
        'optimal_threshold': float(optimal_threshold),
        'optimal_f1': float(optimal_f1),
        'optimal_precision': float(optimal_precision),
        'optimal_recall': float(optimal_recall),
        'default_f1': float(f1_default),
        'improvement': float((f1_optimal_test - f1_default)*100)
    }

def cross_validate_model(X_train, y_train):
    """Realiza validação cruzada 5-fold."""
    print("\n" + "="*60)
    print("VALIDAÇÃO CRUZADA (5-FOLD)")
    print("="*60)
    
    # Criar modelo para validação cruzada
    model = Pipeline(steps=[
        ("scaler", StandardScaler()),
        ("model", LogisticRegression(max_iter=2000, class_weight="balanced", solver="liblinear")),
    ])
    
    # Configurar validação cruzada estratificada
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    
    # Avaliar modelo com múltiplas métricas
    scoring = ['accuracy', 'precision', 'recall', 'f1']
    
    print("\n📊 Resultados da Validação Cruzada:\n")
    
    cv_results = {}
    for metric in scoring:
        scores = cross_val_score(model, X_train, y_train, cv=cv, scoring=metric, n_jobs=-1)
        cv_results[metric] = {
            'mean': float(scores.mean()),
            'std': float(scores.std()),
            'scores': [float(s) for s in scores]
        }
        print(f"  {metric.capitalize():10s}: {scores.mean():.4f} (+/- {scores.std():.4f})")
        print(f"    Folds individuais: {[f'{s:.4f}' for s in scores]}")
    
    print("\n" + "="*60 + "\n")
    
    return cv_results

def save_confusion_matrix(cm, out_png):
    """Salva matriz de confusão como imagem."""
    fig = plt.figure(figsize=(6, 5))
    plt.imshow(cm, cmap="Blues", interpolation='nearest')
    plt.title("Matriz de Confusão", fontsize=14, fontweight='bold')
    plt.colorbar()
    plt.xticks([0,1], ["Legítima", "Phishing"], fontsize=12)
    plt.yticks([0,1], ["Legítima", "Phishing"], fontsize=12)
    plt.xlabel("Predito", fontsize=12)
    plt.ylabel("Real", fontsize=12)
    
    # Adicionar valores nas células
    for i in range(2):
        for j in range(2):
            color = 'white' if cm[i][j] > cm.max() / 2 else 'black'
            plt.text(j, i, str(cm[i][j]), ha="center", va="center", 
                    fontsize=16, fontweight='bold', color=color)
    
    plt.tight_layout()
    fig.savefig(out_png, dpi=300, bbox_inches='tight')
    plt.close(fig)
    print(f"✅ Matriz de confusão salva em: {out_png}")

def save_roc_curve(y_true, y_proba, auc_roc, out_png):
    """Salva curva ROC como imagem."""
    fpr, tpr, _ = roc_curve(y_true, y_proba)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, linewidth=2, label=f'Detecção de Phishing (AUC = {auc_roc:.3f})')
    plt.plot([0, 1], [0, 1], 'k--', linewidth=1, label='Random (AUC = 0.500)')
    plt.xlabel('Taxa de Falsos Positivos (FPR)', fontsize=12)
    plt.ylabel('Taxa de Verdadeiros Positivos (TPR)', fontsize=12)
    plt.title('Curva ROC - Detecção de Phishing', fontsize=14, fontweight='bold')
    plt.legend(loc='lower right', fontsize=11)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"✅ Curva ROC salva em: {out_png}")

def save_pr_curve(y_true, y_proba, auc_pr, out_png):
    """Salva curva Precision-Recall como imagem."""
    precision, recall, _ = precision_recall_curve(y_true, y_proba)
    
    plt.figure(figsize=(8, 6))
    plt.plot(recall, precision, linewidth=2, label=f'Detecção de Phishing (AUC-PR = {auc_pr:.3f})')
    plt.xlabel('Recall', fontsize=12)
    plt.ylabel('Precision', fontsize=12)
    plt.title('Curva Precision-Recall - Detecção de Phishing', fontsize=14, fontweight='bold')
    plt.legend(loc='lower left', fontsize=11)
    plt.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(out_png, dpi=300, bbox_inches='tight')
    plt.close()
    print(f"✅ Curva Precision-Recall salva em: {out_png}")

def print_metrics_summary(metrics, title="Métricas de Desempenho"):
    """Imprime resumo formatado das métricas."""
    print(f"\n📊 {title}:")
    print(f"  Acurácia:  {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
    print(f"  Precisão:  {metrics['precision']:.4f} ({metrics['precision']*100:.2f}%)")
    print(f"  Recall:    {metrics['recall']:.4f} ({metrics['recall']*100:.2f}%)")
    print(f"  F1-Score:  {metrics['f1_score']:.4f}")
    print(f"  AUC-ROC:   {metrics['auc_roc']:.4f}")
    print(f"  AUC-PR:    {metrics['auc_pr']:.4f}")

def main():
    ap = argparse.ArgumentParser(description="Treina modelo PhishGuard com métricas completas e calibração")
    ap.add_argument("--data", required=True, help="CSV path with columns url,label")
    ap.add_argument("--out", default="models/phishguard_lr.joblib", help="Output joblib path")
    ap.add_argument("--skip-cv", action="store_true", help="Skip cross-validation (faster)")
    args = ap.parse_args()

    print("\n" + "="*60)
    print("PHISHGUARD - TREINAMENTO DO MODELO")
    print("="*60)
    
    # Carregar dataset
    print(f"\n📂 Carregando dataset: {args.data}")
    df = load_dataset(args.data)
    print(f"   Total de amostras: {len(df)}")
    print(f"   Legítimas: {(df['label']==0).sum()}")
    print(f"   Phishing:  {(df['label']==1).sum()}")
    
    # Extrair features
    print("\n🔧 Extraindo features...")
    X, y = build_Xy(df)
    print(f"   Shape: {X.shape}")

    # Dividir em treino/validação/teste
    print("\n✂️  Dividindo dataset (60% treino, 20% validação, 20% teste)...")
    X_temp, X_test, y_temp, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    X_train, X_val, y_train, y_val = train_test_split(X_temp, y_temp, test_size=0.25, random_state=42, stratify=y_temp)
    
    print(f"   Treino:     {len(X_train)} amostras")
    print(f"   Validação:  {len(X_val)} amostras")
    print(f"   Teste:      {len(X_test)} amostras")

    # Validação cruzada (opcional)
    cv_results = None
    if not args.skip_cv:
        cv_results = cross_validate_model(X_train, y_train)

    # Treinar modelo
    print("\n🎯 Treinando modelo...")
    pipe = train_pipeline(X_train, y_train)
    print("   ✅ Modelo treinado!")

    # Avaliar no conjunto de treino (com limiar padrão)
    print("\n" + "="*60)
    print("AVALIAÇÃO NO CONJUNTO DE TREINO (limiar=0.5)")
    print("="*60)
    rep_train = evaluate(pipe, X_train, y_train, threshold=0.5, tag="train")
    print_metrics_summary(rep_train, "Treino")

    # Calibrar limiar no conjunto de validação
    optimal_threshold, calibration_info = calibrate_threshold(pipe, X_val, y_val)

    # Avaliar no conjunto de validação (com limiar calibrado)
    print("\n" + "="*60)
    print(f"AVALIAÇÃO NO CONJUNTO DE VALIDAÇÃO (limiar={optimal_threshold:.4f})")
    print("="*60)
    rep_val = evaluate(pipe, X_val, y_val, threshold=optimal_threshold, tag="val")
    print_metrics_summary(rep_val, "Validação")

    # Avaliar no conjunto de teste (com limiar calibrado)
    print("\n" + "="*60)
    print(f"AVALIAÇÃO NO CONJUNTO DE TESTE (limiar={optimal_threshold:.4f})")
    print("="*60)
    rep_test = evaluate(pipe, X_test, y_test, threshold=optimal_threshold, tag="test")
    print_metrics_summary(rep_test, "Teste")

    # Criar diretório de saída
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    out_dir = os.path.dirname(args.out)

    # Salvar modelo
    payload = {
        "pipeline": pipe,
        "feature_order": FEATURE_ORDER,
        "threshold": optimal_threshold,
        "version": "lr-0.2-calibrated",
        "trained_at": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    dump(payload, args.out)
    print(f"\n💾 Modelo salvo em: {args.out}")

    # Salvar relatório completo
    report = {
        "train": rep_train,
        "val": rep_val,
        "test": rep_test,
        "calibration": calibration_info,
        "cross_validation": cv_results,
        "model_path": args.out,
        "dataset_size": len(df),
        "feature_count": X.shape[1]
    }
    
    report_path = os.path.join(out_dir, "report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"📄 Relatório salvo em: {report_path}")

    # Salvar métricas em arquivo separado (para fácil acesso)
    metrics_path = os.path.join(out_dir, "metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump({
            'accuracy': rep_test['accuracy'],
            'precision': rep_test['precision'],
            'recall': rep_test['recall'],
            'f1_score': rep_test['f1_score'],
            'auc_roc': rep_test['auc_roc'],
            'auc_pr': rep_test['auc_pr'],
            'threshold': optimal_threshold
        }, f, indent=2)
    print(f"📊 Métricas salvas em: {metrics_path}")

    # Salvar configuração de limiar
    threshold_path = os.path.join(out_dir, "threshold.json")
    with open(threshold_path, "w", encoding="utf-8") as f:
        json.dump(calibration_info, f, indent=2)
    print(f"🎯 Limiar calibrado salvo em: {threshold_path}")

    # Gerar visualizações
    print("\n📈 Gerando visualizações...")
    
    # Matriz de confusão
    cm = np.array(rep_test["confusion_matrix"])
    save_confusion_matrix(cm, os.path.join(out_dir, "confusion_matrix.png"))
    
    # Curvas ROC e PR
    y_proba_test = pipe.predict_proba(X_test)[:, 1]
    save_roc_curve(y_test, y_proba_test, rep_test['auc_roc'], os.path.join(out_dir, "roc_curve.png"))
    save_pr_curve(y_test, y_proba_test, rep_test['auc_pr'], os.path.join(out_dir, "pr_curve.png"))

    # Resumo final
    print("\n" + "="*60)
    print("✅ TREINAMENTO CONCLUÍDO COM SUCESSO!")
    print("="*60)
    print(f"\nArquivos gerados em: {out_dir}/")
    print(f"  - {os.path.basename(args.out)} (modelo treinado)")
    print(f"  - report.json (relatório completo)")
    print(f"  - metrics.json (métricas principais)")
    print(f"  - threshold.json (limiar calibrado)")
    print(f"  - confusion_matrix.png")
    print(f"  - roc_curve.png")
    print(f"  - pr_curve.png")
    
    print(f"\n🎯 Métricas Finais (Teste):")
    print(f"  Acurácia:  {rep_test['accuracy']:.4f}")
    print(f"  Precisão:  {rep_test['precision']:.4f}")
    print(f"  Recall:    {rep_test['recall']:.4f}")
    print(f"  F1-Score:  {rep_test['f1_score']:.4f}")
    print(f"  AUC-ROC:   {rep_test['auc_roc']:.4f}")
    print(f"  AUC-PR:    {rep_test['auc_pr']:.4f}")
    print(f"  Limiar:    {optimal_threshold:.4f}")
    print("="*60 + "\n")

if __name__ == "__main__":
    main()