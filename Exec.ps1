param(
  [int]$ApiPort = 8000,
  [int]$UiPort  = 3000
)

$ApiDir = "C:\dev\phishguard-api"
$UiDir  = "C:\dev\phishing-ui"

# Verificar se as pastas existem
if (!(Test-Path $ApiDir)) { Write-Host "Pasta da API não encontrada: $ApiDir"; exit 1 }
if (!(Test-Path $UiDir))  { Write-Host "Pasta da UI não encontrada:  $UiDir";  exit 1 }

# ============================================================
# CONFIGURAÇÃO DE VARIÁVEIS DE AMBIENTE
# ============================================================

# Configurar CORS para permitir acesso do frontend
$corsOrigins = "http://localhost:$UiPort,http://127.0.0.1:$UiPort"

# Exibir informações de inicialização
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "PHISHGUARD - SISTEMA DE DETECÇÃO DE PHISHING" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Configuração:" -ForegroundColor Yellow
Write-Host "  API Port:  $ApiPort"
Write-Host "  UI Port:   $UiPort"
Write-Host "  CORS:      $corsOrigins"
Write-Host ""

# ============================================================
# INICIAR API (Backend FastAPI)
# ============================================================

Write-Host "Iniciando API (Backend)..." -ForegroundColor Green

# Comando da API com variáveis de ambiente configuradas
$apiCmd = "cd `"$ApiDir`"; `$env:PHISHGUARD_CORS='$corsOrigins'; `$env:PHISHGUARD_MODEL='models/phishguard_lr.joblib'; `$env:PHISHGUARD_LOG='logs/predictions.csv'; Write-Host ''; Write-Host '=====================================' -ForegroundColor Cyan; Write-Host 'PHISHGUARD API' -ForegroundColor Cyan; Write-Host '=====================================' -ForegroundColor Cyan; Write-Host ''; Write-Host 'CORS configurado: $corsOrigins' -ForegroundColor Green; Write-Host 'Modelo: models/phishguard_lr.joblib' -ForegroundColor Green; Write-Host ''; .\.venv\Scripts\Activate; .\.venv\Scripts\python.exe -m uvicorn app:app --reload --port $ApiPort"

Start-Process powershell -ArgumentList "-NoExit","-Command",$apiCmd | Out-Null

# Aguardar API iniciar
Start-Sleep -Seconds 2

# ============================================================
# INICIAR UI (Frontend Next.js)
# ============================================================

Write-Host "Iniciando UI (Frontend)..." -ForegroundColor Green

# Comando da UI
$uiCmd = "cd `"$UiDir`"; Write-Host ''; Write-Host '=====================================' -ForegroundColor Cyan; Write-Host 'PHISHGUARD UI' -ForegroundColor Cyan; Write-Host '=====================================' -ForegroundColor Cyan; Write-Host ''; Write-Host 'Porta: $UiPort' -ForegroundColor Green; Write-Host 'API: http://localhost:$ApiPort' -ForegroundColor Green; Write-Host ''; npm run dev -- -p $UiPort"

Start-Process powershell -ArgumentList "-NoExit","-Command",$uiCmd | Out-Null

# Aguardar servidores iniciarem
Write-Host ""
Write-Host "Aguardando servidores iniciarem..." -ForegroundColor Yellow
Start-Sleep -Seconds 3

# ============================================================
# ABRIR NAVEGADOR
# ============================================================

Write-Host "Abrindo navegador..." -ForegroundColor Green

# Abrir frontend
Start-Process "http://localhost:$UiPort"

# Aguardar um pouco antes de abrir a segunda aba
Start-Sleep -Milliseconds 500

# Abrir documentação da API (Swagger UI)
Start-Process "http://localhost:$ApiPort/docs"

# ============================================================
# RESUMO FINAL
# ============================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "PHISHGUARD INICIADO COM SUCESSO!" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "URLs Disponíveis:" -ForegroundColor Yellow
Write-Host "  Frontend (UI):      http://localhost:$UiPort"
Write-Host "  Backend (API):      http://localhost:$ApiPort"
Write-Host "  API Docs (Swagger): http://localhost:$ApiPort/docs"
Write-Host "  Health Check:       http://localhost:$ApiPort/health"
Write-Host "  Métricas:           http://localhost:$ApiPort/metrics"
Write-Host ""
Write-Host "Configurações:" -ForegroundColor Yellow
Write-Host "  CORS:   $corsOrigins"
Write-Host "  Modelo: models/phishguard_lr.joblib"
Write-Host "  Logs:   logs/predictions.csv"
Write-Host ""
Write-Host "Dicas:" -ForegroundColor Cyan
Write-Host "  - Para parar os servidores: feche as janelas do PowerShell"
Write-Host "  - Para re-treinar o modelo:"
Write-Host "    cd $ApiDir"
Write-Host "    .\.venv\Scripts\Activate"
Write-Host "    python train.py --data data\dataset.csv --out models\phishguard_lr.joblib"
Write-Host ""
Write-Host "Para o TCC:" -ForegroundColor Magenta
Write-Host "  Métricas:  $ApiDir\models\metrics.json"
Write-Host "  Gráficos:  $ApiDir\models\*.png"
Write-Host "  Limiar:    $ApiDir\models\threshold.json"
Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""
