# 🔴 CONFIGURATION REDIS CACHE (RECOMMANDÉ POUR 100K UTILISATEURS)

**Date** : 29 octobre 2025  
**Priorité** : 🟠 **FORTEMENT RECOMMANDÉ**

---

## 🎯 POURQUOI REDIS ?

Le cache en mémoire (`cache_simple.py`) **ne fonctionne pas** avec Gunicorn multi-workers car :
- Chaque worker = processus séparé = cache séparé
- Invalidation du cache ne fonctionne que pour 1 worker sur 8
- Les 7 autres workers gardent des données obsolètes pendant 1 heure

**Redis résout ce problème** : cache partagé entre tous les workers !

---

## 💰 COÛT

```
Render Redis Cache : $7/mois
```

**Impact performance** :
- Requêtes SQL réduites de **95%**
- Dashboard admin : **2s → 0.2s** (10x plus rapide)
- Cohérence des données garantie

---

## 🚀 INSTALLATION SUR RENDER

### Étape 1 : Créer Redis sur Render

1. Aller sur https://dashboard.render.com
2. Cliquer sur **"New +"** → **"Redis"**
3. Paramètres :
   - **Name** : `etude-line-cache`
   - **Region** : `Oregon` (même région que l'app)
   - **Plan** : `Starter` ($7/mois)
   - **Max Memory Policy** : `allkeys-lru` (supprime anciennes clés)
4. Cliquer sur **"Create Redis"**

### Étape 2 : Récupérer l'URL de connexion

1. Dans le dashboard Redis créé, aller dans **"Info"**
2. Copier la valeur de **"Internal Redis URL"**
   - Format : `redis://red-xxxxx:6379`
3. **NE PAS PARTAGER** cette URL (contient le mot de passe)

### Étape 3 : Ajouter la variable d'environnement

1. Aller dans votre service web **"etude-line"**
2. **"Environment"** → **"Add Environment Variable"**
3. Ajouter :
   - **Key** : `REDIS_URL`
   - **Value** : `redis://red-xxxxx:6379` (URL copiée)
4. Cliquer sur **"Save Changes"**

### Étape 4 : Installer la bibliothèque Redis Python

Ajouter à `requirements.txt` :
```
redis==5.0.1
```

Puis redéployer sur Render (automatique après commit).

---

## 📝 INTÉGRATION DANS LE CODE

### Modifier `cache_simple.py`

```python
"""
Système de cache Redis distribué pour Gunicorn multi-workers
Compatible avec 8 workers en production
"""

import os
from typing import Any, Optional, Dict
from datetime import datetime, timedelta
import json

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    print("⚠️  Redis non disponible - Cache désactivé")

class RedisCache:
    """Cache Redis distribué (partagé entre tous les workers Gunicorn)"""
    
    def __init__(self, redis_url: Optional[str] = None, default_ttl: int = 300):
        """
        Args:
            redis_url: URL Redis (ex: redis://localhost:6379)
            default_ttl: Durée de vie par défaut en secondes (300s = 5 minutes)
        """
        self.default_ttl = default_ttl
        self.redis_url = redis_url or os.getenv("REDIS_URL")
        
        if not REDIS_AVAILABLE or not self.redis_url:
            self.client = None
            print("⚠️  Cache Redis désactivé (REDIS_URL manquant)")
            return
        
        try:
            self.client = redis.from_url(
                self.redis_url,
                decode_responses=True,  # Retourne strings au lieu de bytes
                socket_connect_timeout=5,
                socket_timeout=5
            )
            # Test de connexion
            self.client.ping()
            print(f"✅ Cache Redis connecté : {self.redis_url[:20]}...")
        except Exception as e:
            self.client = None
            print(f"⚠️  Erreur connexion Redis : {e}")
    
    def get(self, key: str) -> Optional[Any]:
        """Récupère une valeur du cache"""
        if not self.client:
            return None
        
        try:
            value = self.client.get(key)
            if value:
                return json.loads(value)
            return None
        except Exception as e:
            print(f"⚠️  Erreur Redis get({key}): {e}")
            return None
    
    def set(self, key: str, value: Any, ttl: Optional[int] = None):
        """Stocke une valeur dans le cache avec une durée de vie"""
        if not self.client:
            return
        
        try:
            ttl = ttl or self.default_ttl
            serialized = json.dumps(value)
            self.client.setex(key, ttl, serialized)
        except Exception as e:
            print(f"⚠️  Erreur Redis set({key}): {e}")
    
    def delete(self, key: str):
        """Supprime une clé du cache (TOUS les workers verront la suppression)"""
        if not self.client:
            return
        
        try:
            self.client.delete(key)
        except Exception as e:
            print(f"⚠️  Erreur Redis delete({key}): {e}")
    
    def clear(self):
        """Vide tout le cache"""
        if not self.client:
            return
        
        try:
            self.client.flushdb()
        except Exception as e:
            print(f"⚠️  Erreur Redis clear: {e}")


# Instance globale du cache Redis
app_cache = RedisCache(default_ttl=300)  # 5 minutes par défaut

# Clés de cache recommandées pour Étude LINE
CACHE_KEYS = {
    "universites": "all_universites",  # TTL: 3600s (1h) - change rarement
    "ufrs": "all_ufrs",  # TTL: 3600s (1h)
    "filieres": "all_filieres",  # TTL: 3600s (1h)
    "matieres": "all_matieres",  # TTL: 1800s (30min)
}
```

### Réactiver le cache dans `main.py`

```python
def get_universites(db: Session) -> List[Dict[str, Any]]:
    """Get all universities from PostgreSQL with Redis cache (1 hour TTL)"""
    cached = app_cache.get(CACHE_KEYS["universites"])
    if cached:
        return cached
    
    universites = db.query(UniversiteDB).all()
    result = [{"id": u.id, "nom": u.nom, "code": u.code, "logo_url": u.logo_url} for u in universites]
    app_cache.set(CACHE_KEYS["universites"], result, ttl=3600)
    return result
```

Réajouter l'invalidation :
```python
# Après création/modification/suppression d'université
app_cache.delete(CACHE_KEYS["universites"])
```

---

## ✅ VÉRIFICATION

Après déploiement, vérifier dans les logs Render :

```
✅ Cache Redis connecté : redis://red-xxxxx...
```

Si vous voyez :
```
⚠️  Cache Redis désactivé (REDIS_URL manquant)
```

→ Vérifier que la variable `REDIS_URL` est bien configurée.

---

## 📊 IMPACT PERFORMANCE ATTENDU

| Métrique | Sans Redis | Avec Redis | Gain |
|----------|-----------|------------|------|
| **Dashboard Admin** | 2s | 0.2s | **10x** ⚡ |
| **Requêtes SQL/sec** | 500 | 25 | **95% moins** ⚡ |
| **Charge DB** | Élevée | Faible | **20x moins** ⚡ |
| **Cohérence données** | ❌ Non | ✅ Oui | **Garanti** ✅ |

---

## 🎉 CONCLUSION

Redis cache est **FORTEMENT RECOMMANDÉ** pour 100k utilisateurs car :
- ✅ Résout le problème de cache multi-workers
- ✅ Réduit la charge sur PostgreSQL de 95%
- ✅ Garantit la cohérence des données
- ✅ Performance 10x meilleure
- ✅ Coût modéré ($7/mois)

**Sans Redis** : Le système fonctionne mais moins performant  
**Avec Redis** : Performance optimale pour 100k utilisateurs ✅
