# Script PowerShell pour surveiller et analyser automatiquement les logs Cowrie

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "SURVEILLANCE AUTOMATIQUE COWRIE" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Vérifier si Python est installé
try {
    $pythonVersion = python --version 2>&1
    Write-Host "✓ Python détecté: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "✗ Python n'est pas installé ou n'est pas dans le PATH" -ForegroundColor Red
    exit 1
}

# Installer watchdog si nécessaire
Write-Host ""
Write-Host "Vérification de la dépendance watchdog..." -ForegroundColor Yellow
pip show watchdog > $null 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Host "Installation de watchdog..." -ForegroundColor Yellow
    pip install watchdog
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ watchdog installé avec succès" -ForegroundColor Green
    } else {
        Write-Host "✗ Erreur lors de l'installation de watchdog" -ForegroundColor Red
        exit 1
    }
} else {
    Write-Host "✓ watchdog déjà installé" -ForegroundColor Green
}

# Vérifier les dépendances du script d'analyse
Write-Host ""
Write-Host "Vérification des dépendances d'analyse..." -ForegroundColor Yellow
$dependencies = @("pandas", "matplotlib", "seaborn")
foreach ($dep in $dependencies) {
    pip show $dep > $null 2>&1
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installation de $dep..." -ForegroundColor Yellow
        pip install $dep
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Démarrage de la surveillance..." -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Lancer le script de surveillance
python sentinelModel/watch_and_analyze.py

Write-Host ""
Write-Host "Surveillance terminée." -ForegroundColor Yellow
