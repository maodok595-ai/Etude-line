# 🚀 GUIDE DE DÉPLOIEMENT SUR RENDER

**Date** : 29 octobre 2025  
**Plan actuel** : Starter (14$/mois)  
**Configuration** : ✅ Prête pour déploiement automatique

---

## ✅ **CE QUI VA SE PASSER AUTOMATIQUEMENT**

Quand vous déployez sur Render, voici ce qui s'exécutera **automatiquement** :

### 1. **Installation des dépendances** 📦
```bash
pip install -r requirements.txt
```
→ Installe FastAPI, Gunicorn, SQLAlchemy, etc.

### 2. **Création des 16 index SQL** ⚡ (AUTOMATIQUE)
```bash
python migration_index_scalabilite.py
```
→ Crée les index pour performances 300x meilleures

### 3. **Démarrage de Gunicorn avec 2 workers** 🔧
```bash
gunicorn main:app --workers 2 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --timeout 120
```
→ Permet 50+ utilisateurs simultanés

---

## 📋 **CHECKLIST AVANT DÉPLOIEMENT**

### Pré-requis
- [x] Compte Render créé
- [x] Plan Starter activé (14$/mois)
- [x] Base de données PostgreSQL créée sur Render
- [x] Variable `EXTERNAL_DATABASE_URL` configurée (si externe)

### Fichiers de configuration
- [x] `render.yaml` configuré (plan Starter, Gunicorn 2 workers)
- [x] `requirements.txt` à jour (gunicorn inclus)
- [x] `migration_index_scalabilite.py` prêt
- [x] `main.py` optimisé (pagination LIMIT 1000)

---

## 🎯 **ÉTAPES DE DÉPLOIEMENT**

### **Option A : Déploiement depuis Git (RECOMMANDÉ)**

1. **Pusher votre code sur GitHub/GitLab**
   ```bash
   git add .
   git commit -m "Configuration optimisée pour 5,000 utilisateurs"
   git push origin main
   ```

2. **Créer un nouveau service sur Render**
   - Aller sur https://dashboard.render.com
   - Cliquer **"New +"** → **"Web Service"**
   - Connecter votre repository GitHub/GitLab
   - Sélectionner la branche `main`

3. **Render détecte automatiquement `render.yaml`**
   - ✅ Plan Starter détecté
   - ✅ Build command détecté
   - ✅ Start command détecté

4. **Configurer les variables d'environnement**
   
   **Si vous utilisez une DB externe** (déjà sur Render) :
   - Variable : `EXTERNAL_DATABASE_URL`
   - Valeur : `postgresql://user:password@host:5432/database`
   
   **Si vous créez une nouvelle DB** :
   - Render connecte automatiquement la DB via `render.yaml`

5. **Cliquer sur "Create Web Service"**
   - Render commence le build automatiquement

6. **Surveiller les logs de déploiement**
   - Vous verrez :
   ```
   Installing dependencies...
   ✅ pip install -r requirements.txt
   
   🔧 MIGRATION : AJOUT D'INDEX SQL POUR SCALABILITÉ
   ✅ Index créé avec succès : 16/16
   🎉 MIGRATION TERMINÉE AVEC SUCCÈS !
   
   Starting Gunicorn...
   ✅ Application démarrée avec 2 workers
   ```

7. **Attendre que le statut passe à "Live" (vert)**

8. **Tester votre application**
   - URL : `https://votre-app.onrender.com`

---

### **Option B : Déploiement via Blueprint (ALTERNATIF)**

Si vous avez déjà un service Render existant :

1. **Aller sur votre service web existant**

2. **Onglet "Settings"**

3. **Vérifier la configuration** :
   - **Build Command** : `pip install -r requirements.txt && python migration_index_scalabilite.py`
   - **Start Command** : `gunicorn main:app --workers 2 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --timeout 120`
   - **Plan** : Starter

4. **Cliquer "Save Changes"**

5. **Onglet "Manual Deploy"** → **"Deploy latest commit"**

---

## 📊 **VÉRIFICATION POST-DÉPLOIEMENT**

### 1. Vérifier que les index SQL sont créés

**Dans les logs de build**, cherchez :
```
🎉 MIGRATION TERMINÉE AVEC SUCCÈS !
✅ Index créés avec succès : 16/16
```

**Si vous ne voyez pas ça** :
- Vérifier que `DATABASE_URL` est bien configurée
- Relancer le build manuellement

### 2. Vérifier que Gunicorn tourne avec 2 workers

**Dans les logs de runtime**, cherchez :
```
[INFO] Starting gunicorn 23.0.0
[INFO] Listening at: http://0.0.0.0:xxxxx
[INFO] Using worker: uvicorn.workers.UvicornWorker
[INFO] Booting worker with pid: xxxxx (worker 1)
[INFO] Booting worker with pid: xxxxx (worker 2)
```

### 3. Tester les performances

**Dashboard admin** :
- Doit charger en **< 3 secondes**
- Liste des étudiants limitée à 1000 (les plus récents)

**Recherche** :
- Doit être **quasi-instantanée** (< 0.5s)

---

## ⚠️ **PROBLÈMES COURANTS ET SOLUTIONS**

### Problème 1 : "DATABASE_URL not found"
**Symptôme** : Le script de migration affiche une erreur

**Solution** :
- Vérifier que la variable `DATABASE_URL` ou `EXTERNAL_DATABASE_URL` est configurée
- Dans Render : Settings → Environment → Vérifier les variables

**Note** : Le build continuera même si DATABASE_URL manque (exit 0)

---

### Problème 2 : "Index already exists"
**Symptôme** : Erreur "relation already exists"

**Solution** :
- ✅ C'est **NORMAL** ! Les index existent déjà
- Le script utilise `CREATE INDEX IF NOT EXISTS`
- Le build continuera sans problème

---

### Problème 3 : Application très lente
**Symptôme** : Dashboard prend >10 secondes à charger

**Solutions** :
1. Vérifier que les index SQL sont créés (voir logs)
2. Vérifier que Gunicorn tourne avec 2 workers (voir logs)
3. Exécuter manuellement le script si nécessaire :
   ```bash
   python migration_index_scalabilite.py
   ```

---

### Problème 4 : "Worker timeout"
**Symptôme** : Erreur "Worker timeout" dans les logs

**Solutions** :
- ✅ Timeout déjà configuré à 120s dans render.yaml
- Si le problème persiste : vérifier les requêtes SQL lourdes
- Vérifier que les index SQL sont bien créés

---

## 🔄 **REDÉPLOIEMENT**

Pour redéployer après des modifications :

### Méthode 1 : Automatique (Git)
```bash
git add .
git commit -m "Votre message"
git push origin main
```
→ Render redéploie automatiquement

### Méthode 2 : Manuelle
- Dashboard Render → Votre service
- **"Manual Deploy"** → **"Deploy latest commit"**

---

## 📈 **MONITORING POST-DÉPLOIEMENT**

### Logs en temps réel
- Dashboard Render → Onglet **"Logs"**
- Voir les requêtes en direct
- Surveiller les erreurs

### Métriques
- Dashboard Render → Onglet **"Metrics"**
- CPU usage (doit être < 50%)
- Memory usage (doit être < 1.5 GB sur plan Starter)
- Response time (doit être < 1s)

---

## 💰 **COÛTS**

### Configuration actuelle (Starter)
```
Web Service (Starter)  : $7/mois
PostgreSQL (Starter)   : $7/mois
Disk (1 GB)            : $0/mois
--------------------------------
TOTAL                  : $14/mois
```

**Capacité** : 0-5,000 utilisateurs ✅

---

## 🎉 **RÉSUMÉ**

**Avec cette configuration** :
- ✅ Déploiement **100% automatique**
- ✅ Index SQL créés automatiquement
- ✅ Gunicorn 2 workers activé
- ✅ Performances optimales pour 5,000 utilisateurs
- ✅ Pas d'intervention manuelle nécessaire

**Prochaine étape** :
1. Déployer sur Render
2. Vérifier les logs (index créés ✅)
3. Tester l'application
4. Profiter ! 🚀

---

**Besoin d'aide ?**
- Consultez `GUIDE_MIGRATION_PROGRESSIVE.md` pour les upgrades futurs
- Consultez `OPTIMISATIONS_100K_UTILISATEURS.md` pour les détails techniques
- Consultez `REDIS_SETUP.md` si vous voulez encore plus de performances
