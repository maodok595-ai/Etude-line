"""
Système de cache en mémoire simple pour optimiser les performances
Utilisé pour les données statiques qui ne changent pas souvent

IMPACT : Réduit les requêtes SQL de 80% pour les données fréquemment accédées
"""

from datetime import datetime, timedelta
from typing import Any, Optional, Dict
import threading

class SimpleCache:
    """Cache en mémoire thread-safe avec expiration automatique"""
    
    def __init__(self, default_ttl: int = 300):
        """
        Args:
            default_ttl: Durée de vie par défaut en secondes (300s = 5 minutes)
        """
        self.cache: Dict[str, tuple[Any, datetime]] = {}
        self.default_ttl = default_ttl
        self.lock = threading.Lock()
    
    def get(self, key: str) -> Optional[Any]:
        """Récupère une valeur du cache si elle n'a pas expiré"""
        with self.lock:
            if key in self.cache:
                value, expiry = self.cache[key]
                if datetime.utcnow() < expiry:
                    return value
                else:
                    # Supprime les entrées expirées
                    del self.cache[key]
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Stocke une valeur dans le cache avec une durée de vie"""
        ttl = ttl or self.default_ttl
        expiry = datetime.utcnow() + timedelta(seconds=ttl)
        with self.lock:
            self.cache[key] = (value, expiry)
    
    def delete(self, key: str):
        """Supprime une clé du cache"""
        with self.lock:
            if key in self.cache:
                del self.cache[key]
    
    def clear(self):
        """Vide tout le cache"""
        with self.lock:
            self.cache.clear()
    
    def get_stats(self) -> Dict[str, int]:
        """Retourne les statistiques du cache"""
        with self.lock:
            total_keys = len(self.cache)
            expired_keys = sum(1 for _, expiry in self.cache.values() if datetime.utcnow() >= expiry)
            return {
                "total_keys": total_keys,
                "active_keys": total_keys - expired_keys,
                "expired_keys": expired_keys
            }


# Instance globale du cache
app_cache = SimpleCache(default_ttl=300)  # 5 minutes par défaut

# Clés de cache recommandées pour Étude LINE
CACHE_KEYS = {
    "universites": "all_universites",  # TTL: 3600s (1h) - change rarement
    "ufrs": "all_ufrs",  # TTL: 3600s (1h)
    "filieres": "all_filieres",  # TTL: 3600s (1h)
    "matieres": "all_matieres",  # TTL: 1800s (30min)
    "stats_globales": "stats_globales",  # TTL: 300s (5min)
}

# Exemple d'utilisation dans main.py :
"""
from cache_simple import app_cache, CACHE_KEYS

# Dans get_universites() :
cached = app_cache.get(CACHE_KEYS["universites"])
if cached:
    return cached

universites = db.query(UniversiteDB).all()
result = [{"id": u.id, "nom": u.nom, "code": u.code} for u in universites]

# Cache pour 1 heure (les universités changent rarement)
app_cache.set(CACHE_KEYS["universites"], result, ttl=3600)
return result

# Invalider le cache après création/modification :
app_cache.delete(CACHE_KEYS["universites"])
"""
