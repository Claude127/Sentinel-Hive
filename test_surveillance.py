"""
Script de test pour la surveillance automatique
Crée un fichier de test dans exports/cowrie pour vérifier le fonctionnement
"""
import os
import time
import shutil
from pathlib import Path
from datetime import datetime

def test_surveillance():
    """Teste la surveillance en créant un fichier de test"""
    
    # Chemins
    source_file = Path('sentinelModel/logs/cowrie.json.2024-10-23')
    test_dir = Path('exports/cowrie')
    test_file = test_dir / f'cowrie.json.{datetime.now().strftime("%Y-%m-%d")}'
    
    print("=" * 60)
    print("TEST DE LA SURVEILLANCE AUTOMATIQUE")
    print("=" * 60)
    print()
    
    # Vérifier que le fichier source existe
    if not source_file.exists():
        print(f"❌ Fichier source introuvable: {source_file}")
        return False
    
    print(f"✓ Fichier source trouvé: {source_file}")
    
    # Créer le dossier de destination si nécessaire
    test_dir.mkdir(parents=True, exist_ok=True)
    print(f"✓ Dossier de destination: {test_dir.absolute()}")
    
    # Copier le fichier
    print(f"\nCopie du fichier de test vers: {test_file.name}")
    print("→ Cela devrait déclencher l'analyse automatique si la surveillance est active...")
    print()
    
    try:
        shutil.copy2(source_file, test_file)
        print(f"✓ Fichier copié avec succès!")
        print(f"\nSi la surveillance est active, l'analyse devrait démarrer dans quelques secondes.")
        print(f"Consultez le fichier 'sentinelModel/watch_log.txt' pour voir les logs.")
        return True
    except Exception as e:
        print(f"❌ Erreur lors de la copie: {e}")
        return False

if __name__ == '__main__':
    success = test_surveillance()
    print()
    print("=" * 60)
    if success:
        print("TEST TERMINÉ - Fichier créé avec succès")
    else:
        print("TEST ÉCHOUÉ")
    print("=" * 60)
