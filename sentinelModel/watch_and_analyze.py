"""
Script de surveillance automatique pour l'analyse des logs Cowrie
Surveille le dossier exports/cowrie et lance l'analyse à chaque nouveau fichier
"""
import os
import time
import subprocess
from pathlib import Path
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime

# Configuration
WATCH_DIRECTORY = 'exports/cowrie'
ANALYSIS_SCRIPT = 'sentinelModel/analysisplus.py'
LOG_FILE = 'sentinelModel/watch_log.txt'

class CowrieLogHandler(FileSystemEventHandler):
    """Gestionnaire d'événements pour les fichiers de logs Cowrie"""
    
    def __init__(self):
        self.last_analysis_time = 0
        self.cooldown_seconds = 10  # Éviter les analyses multiples rapides
        
    def log_message(self, message):
        """Enregistre un message dans le fichier de log"""
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        log_entry = f"[{timestamp}] {message}\n"
        print(log_entry.strip())
        
        try:
            with open(LOG_FILE, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except Exception as e:
            print(f"Erreur lors de l'écriture du log: {e}")
    
    def should_trigger_analysis(self, file_path):
        """Détermine si l'analyse doit être déclenchée"""
        # Vérifier le cooldown
        current_time = time.time()
        if current_time - self.last_analysis_time < self.cooldown_seconds:
            return False
        
        # Vérifier que c'est un fichier JSON Cowrie
        filename = os.path.basename(file_path)
        if not (filename.startswith('cowrie') and 
                (filename.endswith('.json') or '.json.' in filename)):
            return False
        
        # Vérifier que le fichier existe et n'est pas vide
        try:
            if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
                return True
        except Exception:
            return False
        
        return False
    
    def run_analysis(self):
        """Lance le script d'analyse"""
        self.last_analysis_time = time.time()
        self.log_message("=" * 60)
        self.log_message("DÉCLENCHEMENT DE L'ANALYSE AUTOMATIQUE")
        self.log_message("=" * 60)
        
        try:
            # Lancer le script d'analyse
            result = subprocess.run(
                ['python', ANALYSIS_SCRIPT],
                capture_output=True,
                text=True,
                timeout=300  # Timeout de 5 minutes
            )
            
            if result.returncode == 0:
                self.log_message("✓ Analyse terminée avec succès")
                if result.stdout:
                    self.log_message(f"Sortie:\n{result.stdout}")
            else:
                self.log_message(f"✗ Erreur lors de l'analyse (code: {result.returncode})")
                if result.stderr:
                    self.log_message(f"Erreur:\n{result.stderr}")
                    
        except subprocess.TimeoutExpired:
            self.log_message("✗ Timeout: L'analyse a pris trop de temps")
        except Exception as e:
            self.log_message(f"✗ Exception lors de l'exécution: {e}")
        
        self.log_message("=" * 60 + "\n")
    
    def on_created(self, event):
        """Appelé quand un nouveau fichier est créé"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        filename = os.path.basename(file_path)
        
        self.log_message(f"Nouveau fichier détecté: {filename}")
        
        # Attendre un peu que le fichier soit complètement écrit
        time.sleep(2)
        
        if self.should_trigger_analysis(file_path):
            self.log_message(f"→ Fichier valide, lancement de l'analyse...")
            self.run_analysis()
        else:
            self.log_message(f"→ Fichier ignoré (pas un log Cowrie ou cooldown actif)")
    
    def on_modified(self, event):
        """Appelé quand un fichier est modifié"""
        if event.is_directory:
            return
        
        file_path = event.src_path
        filename = os.path.basename(file_path)
        
        # Ignorer les fichiers de log et offset
        if filename.startswith('.') or filename.endswith('.log') or 'offset' in filename:
            return
        
        self.log_message(f"Fichier modifié: {filename}")
        
        # Attendre que le fichier soit complètement écrit
        time.sleep(2)
        
        if self.should_trigger_analysis(file_path):
            self.log_message(f"→ Modification significative, lancement de l'analyse...")
            self.run_analysis()

def main():
    """Fonction principale"""
    # Vérifier que les chemins existent
    watch_path = Path(WATCH_DIRECTORY)
    analysis_script_path = Path(ANALYSIS_SCRIPT)
    
    if not watch_path.exists():
        print(f"[ERREUR] Le dossier à surveiller n'existe pas: {watch_path}")
        print(f"Création du dossier...")
        watch_path.mkdir(parents=True, exist_ok=True)
    
    if not analysis_script_path.exists():
        print(f"[ERREUR] Le script d'analyse n'existe pas: {analysis_script_path}")
        return
    
    # Créer le gestionnaire et l'observateur
    event_handler = CowrieLogHandler()
    observer = Observer()
    observer.schedule(event_handler, str(watch_path), recursive=False)
    
    # Démarrer la surveillance
    observer.start()
    
    print("=" * 70)
    print("SURVEILLANCE AUTOMATIQUE DES LOGS COWRIE")
    print("=" * 70)
    print(f"Dossier surveillé: {watch_path.absolute()}")
    print(f"Script d'analyse: {analysis_script_path.absolute()}")
    print(f"Fichier de log: {LOG_FILE}")
    print(f"Cooldown entre analyses: {event_handler.cooldown_seconds} secondes")
    print("\nEn attente de nouveaux fichiers...")
    print("Appuyez sur Ctrl+C pour arrêter\n")
    
    event_handler.log_message("Surveillance démarrée")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\nArrêt de la surveillance...")
        event_handler.log_message("Surveillance arrêtée par l'utilisateur")
        observer.stop()
    
    observer.join()
    print("Surveillance terminée.")

if __name__ == '__main__':
    main()
