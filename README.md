# 🛡️ Sentinel-Hive - Système d'Analyse Cowrie Honeypot

Système d'analyse automatique et avancée des logs Cowrie avec surveillance en temps réel, détection de menaces et génération de rapports détaillés.

---

## 📋 Table des matières

1. [Vue d'ensemble](#-vue-densemble)
2. [Installation rapide](#-installation-rapide)
3. [Fonctionnement](#-fonctionnement)
4. [Automatisation](#-automatisation)
5. [Procédures](#-procédures)
6. [Configuration](#-configuration)
7. [Dépannage](#-dépannage)

---

## 🎯 Vue d'ensemble

### Capacités du système

**Analyse avancée** :
- 15 catégories d'attaques (Reconnaissance, Download, Destructive, Persistence, Privilege Escalation, etc.)
- 16 familles de malware (Mirai, Gafgyt, XorDDoS, Tsunami, Coinminer, Webshell, Ransomware, etc.)
- Mapping MITRE ATT&CK (15 techniques)
- Extraction d'IOCs (URLs, IPs, domaines, emails, hashes, fichiers)
- Scoring de menace (0-100) avec classification par niveau de risque
- Évaluation de sophistication (Script Kiddie → APT)

**Surveillance automatique** :
- Détection en temps réel des nouveaux fichiers dans `exports/cowrie/`
- Analyse automatique déclenchée à chaque nouveau fichier
- Cooldown intelligent (10 secondes entre analyses)
- Logging complet dans `sentinelModel/watch_log.txt`

**Rapports générés** :
- HTML interactif avec statistiques et tableaux
- CSV détaillé pour analyse approfondie
- 7 visualisations PNG haute résolution (300 DPI)

### Architecture du système

```
Cowrie Honeypot
    ↓
Logstash (pipeline)
    ↓
Elasticsearch
    ↓
Export quotidien (export-cowrie-daily.ps1)
    ↓
exports/cowrie/ (fichiers JSON)
    ↓
Surveillance automatique (watch_and_analyze.py)
    ↓
Analyse (analysisplus.py)
    ↓
Rapports (reports/)
```

### Structure des fichiers

```
Sentinel-Hive/
├── sentinelModel/
│   ├── analysisplus.py          # Moteur d'analyse
│   ├── watch_and_analyze.py     # Surveillance automatique
│   ├── requirements.txt         # Dépendances Python
│   └── watch_log.txt            # Logs de surveillance
├── exports/cowrie/              # Dossier surveillé (source des données)
│   ├── cowrie.json              # Export actuel
│   └── cowrie.json.YYYY-MM-DD   # Exports quotidiens
├── reports/                     # Rapports générés
│   ├── cowrie_analysis_report.html
│   ├── cowrie_analysis_detailed.csv
│   └── *.png (7 visualisations)
├── logstash/pipeline/           # Configuration Logstash
├── start_cowrie_watch.bat       # Lanceur surveillance
└── test_surveillance.py         # Script de test
```

---

## ⚡ Installation rapide

### Prérequis
- Python 3.8+
- pip

### Installation en 1 commande

**Windows** :
```cmd
pip install -r sentinelModel/requirements.txt
```

**Linux/Mac** :
```bash
pip install -r sentinelModel/requirements.txt
```

### Dépendances installées
- pandas (analyse de données)
- matplotlib & seaborn (visualisations)
- watchdog (surveillance fichiers)
- numpy & python-dateutil (calculs et dates)

### Vérification

```bash
python test_surveillance.py
```

---

## 🔍 Fonctionnement

### 1. Surveillance automatique (recommandé)

**Démarrage** :
```cmd
# Windows - Double-clic
start_cowrie_watch.bat

# Ou ligne de commande
python sentinelModel/watch_and_analyze.py
```

**Ce qui se passe** :
1. Le système surveille le dossier `exports/cowrie/`
2. Dès qu'un nouveau fichier apparaît (ou est modifié) :
   - Attente de 2 secondes (fichier complètement écrit)
   - Vérification du format (cowrie*.json*)
   - Vérification du cooldown (10 secondes minimum)
   - Lancement automatique de l'analyse
3. Génération des rapports dans `reports/`
4. Logging dans `sentinelModel/watch_log.txt`

**Formats supportés** :
- `cowrie.json` (export actuel)
- `cowrie.json.YYYY-MM-DD` (exports quotidiens)
- `cowrie_N.json` (exports numérotés)
- Tous fichiers `cowrie*.json*`

**Arrêt** :
```
Ctrl+C
```

### 2. Analyse manuelle

Pour analyser ponctuellement les fichiers dans `exports/cowrie/` :

```bash
python sentinelModel/analysisplus.py
```

**Note** : L'analyse manuelle et automatique utilisent la même source de données (`exports/cowrie/`).

### 3. Rapports générés

Après chaque analyse, 3 types de rapports sont créés dans `reports/` :

**A. Rapport HTML** (`cowrie_analysis_report.html`)
- Statistiques globales (sessions, IPs, commandes, score moyen)
- Répartition par niveau de risque (Critique/Élevé/Faible)
- Top 5 des menaces les plus graves
- Catégories d'attaque actives
- Familles de malware détectées
- Tableau complet de toutes les sessions

**B. Export CSV** (`cowrie_analysis_detailed.csv`)
Contient pour chaque session :
- Identifiants (session_id, src_ip, command_count)
- Classification (intent, skill_level, malware_family, threat_score)
- Scores par catégorie (15 colonnes : recon, download, destructive, etc.)
- IOCs extraits (URLs, IPs, domaines, emails, hashes, fichiers)
- Patterns suspects (ports, chemins, encodage, obfuscation)
- Techniques MITRE ATT&CK
- Échantillons de commandes

**C. Visualisations PNG** (7 graphiques haute résolution)
1. `attack_intent_distribution.png` - Distribution des intentions par gravité
2. `attacker_skill_level.png` - Niveaux de sophistication (pie chart)
3. `top_attacker_ips.png` - Top 15 IPs par score de menace
4. `threat_score_distribution.png` - Distribution des scores avec zones de risque
5. `attack_categories_heatmap.png` - Répartition des 15 catégories
6. `malware_families.png` - Familles de malware identifiées
7. `skill_vs_threat.png` - Corrélation sophistication vs menace

---

## 🤖 Automatisation

### Automatisation complète du pipeline

**Pipeline actuel** :
```
Cowrie → Logstash → Elasticsearch
```

**Pipeline avec export quotidien** :
```
Elasticsearch → export-cowrie-daily.ps1 → exports/cowrie/
```

**Pipeline avec surveillance automatique** :
```
exports/cowrie/ → watch_and_analyze.py → analysisplus.py → reports/
```

**Pipeline complet automatisé** :
```
Cowrie → Logstash → Elasticsearch → Export quotidien → Surveillance → Analyse → Rapports
```

### Automatisation au démarrage Windows

#### Méthode 1 : Planificateur de tâches (recommandé)

1. Ouvrez **Planificateur de tâches** Windows
2. Cliquez sur **Créer une tâche de base**
3. Configurez :
   - **Nom** : `Cowrie Auto Analysis`
   - **Déclencheur** : `Au démarrage de l'ordinateur`
   - **Action** : `Démarrer un programme`
   - **Programme** : `python`
   - **Arguments** : `sentinelModel/watch_and_analyze.py`
   - **Dossier de départ** : Chemin complet vers Sentinel-Hive (ex: `C:\Sentinel-Hive`)
4. Cochez **Exécuter même si l'utilisateur n'est pas connecté**
5. Validez

**Résultat** : La surveillance démarre automatiquement à chaque démarrage de Windows.

#### Méthode 2 : Dossier Démarrage

1. Créez un raccourci vers `start_cowrie_watch.bat`
2. Appuyez sur `Win+R` et tapez : `shell:startup`
3. Copiez le raccourci dans le dossier qui s'ouvre

**Résultat** : La surveillance démarre à chaque connexion utilisateur.

### Automatisation de l'export Elasticsearch

Le script `export-cowrie-daily.ps1` exporte quotidiennement les logs depuis Elasticsearch vers `exports/cowrie/`.

**Planification** :
1. Ouvrez **Planificateur de tâches**
2. Créez une tâche quotidienne
3. Programme : `powershell.exe`
4. Arguments : `-File "C:\chemin\vers\export-cowrie-daily.ps1"`
5. Heure : 23h59 (ou selon vos besoins)

---

## 📋 Procédures

### Procédure 1 : Démarrage initial

```bash
# 1. Installer les dépendances
pip install -r sentinelModel/requirements.txt

# 2. Tester le système
python test_surveillance.py

# 3. Démarrer la surveillance
python sentinelModel/watch_and_analyze.py
```

### Procédure 2 : Analyse ponctuelle

```bash
# Analyser les fichiers actuels dans exports/cowrie/
python sentinelModel/analysisplus.py

# Consulter les rapports
cd reports
start cowrie_analysis_report.html  # Windows
```

### Procédure 3 : Vérification du système

```bash
# 1. Vérifier que le dossier surveillé existe
dir exports\cowrie

# 2. Vérifier les logs de surveillance
type sentinelModel\watch_log.txt

# 3. Tester avec un fichier factice
python test_surveillance.py

# 4. Vérifier les rapports générés
dir reports
```

### Procédure 4 : Déploiement sur nouvelle machine

```bash
# 1. Cloner le projet
git clone <votre-repo>
cd Sentinel-Hive

# 2. Installer les dépendances
pip install -r sentinelModel/requirements.txt

# 3. Créer les dossiers nécessaires (si absents)
mkdir exports\cowrie
mkdir reports

# 4. Tester
python test_surveillance.py

# 5. Configurer l'automatisation (voir section Automatisation)

# 6. Démarrer
python sentinelModel/watch_and_analyze.py
```

### Procédure 5 : Maintenance régulière

```bash
# Nettoyer les anciens rapports (optionnel)
del reports\*.html
del reports\*.csv
del reports\*.png

# Nettoyer les logs de surveillance
del sentinelModel\watch_log.txt

# Mettre à jour les dépendances
pip install --upgrade -r sentinelModel/requirements.txt

# Vérifier l'espace disque
dir exports\cowrie
```

---

## ⚙️ Configuration

### Configuration de l'analyse (analysisplus.py)

```python
# Dossier source des logs
LOG_DIRECTORY = 'exports/cowrie'

# Dossier de sortie des rapports
OUTPUT_DIR = 'reports'
```

### Configuration de la surveillance (watch_and_analyze.py)

```python
# Dossier à surveiller
WATCH_DIRECTORY = 'exports/cowrie'

# Script d'analyse à lancer
ANALYSIS_SCRIPT = 'sentinelModel/analysisplus.py'

# Fichier de log
LOG_FILE = 'sentinelModel/watch_log.txt'

# Délai minimum entre deux analyses (secondes)
cooldown_seconds = 10
```

### Personnalisation de la détection

**Ajouter des mots-clés** (dans `analysisplus.py`) :
```python
KEYWORDS = {
    'recon': {
        'whoami', 'uname', 'ls', 'pwd',
        # Ajoutez vos mots-clés ici
        'nouveau_mot_cle',
    },
    # ...
}
```

**Ajouter des familles de malware** :
```python
MALWARE_PATTERNS = {
    'mirai': ['busybox', 'ECCHI', 'MIRAI'],
    'votre_malware': ['pattern1', 'pattern2'],
    # ...
}
```

**Modifier le cooldown** :
```python
# Dans watch_and_analyze.py
self.cooldown_seconds = 30  # 30 secondes au lieu de 10
```

**Modifier le timeout d'analyse** :
```python
# Dans watch_and_analyze.py
result = subprocess.run(
    ['python', ANALYSIS_SCRIPT],
    timeout=600  # 10 minutes au lieu de 5
)
```

---

## 🐛 Dépannage

### Problème : Aucun fichier détecté

**Symptômes** :
- La surveillance tourne mais aucune analyse ne se lance
- Message : "Aucun fichier de log trouvé"

**Solutions** :
1. Vérifiez que `exports/cowrie/` existe :
   ```bash
   dir exports\cowrie
   ```
2. Vérifiez les permissions du dossier
3. Consultez les logs :
   ```bash
   type sentinelModel\watch_log.txt
   ```
4. Testez manuellement :
   ```bash
   python test_surveillance.py
   ```

### Problème : Analyses trop fréquentes

**Symptômes** :
- Plusieurs analyses se lancent pour le même fichier
- Logs montrent des analyses répétées

**Solution** :
Augmentez le cooldown dans `watch_and_analyze.py` :
```python
self.cooldown_seconds = 30  # ou plus
```

### Problème : Erreur lors de l'analyse

**Symptômes** :
- Message d'erreur dans `watch_log.txt`
- Pas de rapports générés

**Solutions** :
1. Testez l'analyse manuellement :
   ```bash
   python sentinelModel/analysisplus.py
   ```
2. Vérifiez les dépendances :
   ```bash
   pip install --upgrade -r sentinelModel/requirements.txt
   ```
3. Consultez les logs détaillés :
   ```bash
   type sentinelModel\watch_log.txt
   ```

### Problème : Dépendances manquantes

**Symptômes** :
- `ModuleNotFoundError: No module named 'pandas'`
- Erreurs d'import

**Solution** :
```bash
pip install -r sentinelModel/requirements.txt
```

### Problème : Rapports non générés

**Symptômes** :
- L'analyse se termine mais pas de fichiers dans `reports/`

**Solutions** :
1. Vérifiez que le dossier `reports/` existe :
   ```bash
   mkdir reports
   ```
2. Vérifiez les permissions d'écriture
3. Consultez les erreurs dans la console ou `watch_log.txt`

### Problème : Surveillance s'arrête

**Symptômes** :
- La surveillance se ferme toute seule
- Pas de processus Python actif

**Solutions** :
1. Vérifiez les erreurs dans `watch_log.txt`
2. Lancez en mode debug :
   ```bash
   python sentinelModel/watch_and_analyze.py
   ```
3. Vérifiez que Python ne se ferme pas (timeout, erreur, etc.)

---

## 📊 Logs et monitoring

### Logs de surveillance

Fichier : `sentinelModel/watch_log.txt`

**Exemple** :
```
[2024-12-17 15:30:45] Surveillance démarrée
[2024-12-17 15:30:45] Nouveau fichier détecté: cowrie.json.2024-12-17
[2024-12-17 15:30:47] → Fichier valide, lancement de l'analyse...
[2024-12-17 15:30:47] ============================================================
[2024-12-17 15:30:47] DÉCLENCHEMENT DE L'ANALYSE AUTOMATIQUE
[2024-12-17 15:30:47] ============================================================
[2024-12-17 15:31:15] ✓ Analyse terminée avec succès
```

### Monitoring en temps réel

```bash
# Windows
powershell Get-Content sentinelModel\watch_log.txt -Wait -Tail 20

# Linux/Mac
tail -f sentinelModel/watch_log.txt
```

---

## 📈 Statistiques du système

- **15 catégories d'attaques** détectées
- **16 familles de malware** identifiées
- **15 techniques MITRE ATT&CK** mappées
- **6 types d'IOCs** extraits (URLs, IPs, domaines, emails, hashes, fichiers)
- **7 visualisations** générées par analyse
- **3 formats de rapports** (HTML, CSV, PNG)

---

## 🔗 Ressources

**Fichiers principaux** :
- `sentinelModel/analysisplus.py` - Moteur d'analyse (1400+ lignes)
- `sentinelModel/watch_and_analyze.py` - Surveillance automatique (200+ lignes)
- `sentinelModel/requirements.txt` - Dépendances Python

**Scripts utiles** :
- `start_cowrie_watch.bat` - Lanceur surveillance Windows
- `test_surveillance.py` - Script de test
- `export-cowrie-daily.ps1` - Export quotidien Elasticsearch

---

## 📞 Support

**En cas de problème** :
1. Consultez la section [Dépannage](#-dépannage)
2. Vérifiez les logs dans `sentinelModel/watch_log.txt`
3. Testez avec `python test_surveillance.py`
4. Vérifiez que les dépendances sont installées

---

**Version** : 2.0  
**Dernière mise à jour** : 2024-12-17  
**Auteur** : Sentinel-Hive Project
