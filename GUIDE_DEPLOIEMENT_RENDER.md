# 🚀 Guide de Déploiement sur Render

Ce guide vous explique comment déployer **Étude LINE** sur Render.

---

## ✅ Corrections Appliquées

Les problèmes suivants ont été corrigés pour permettre le déploiement :

### 1. **Port Dynamique**
- ✅ L'application utilise maintenant la variable `PORT` de Render
- ✅ Le port s'adapte automatiquement (5000 en local, assigné par Render en production)

### 2. **Mode Production**
- ✅ Le flag `reload=True` est désactivé en production
- ✅ Détection automatique de l'environnement (RENDER)

### 3. **Requirements.txt**
- ✅ Doublons supprimés
- ✅ Fichier nettoyé et optimisé

### 4. **Configuration Render**
- ✅ Fichier `render.yaml` créé avec toutes les configurations

---

## 📋 Étapes de Déploiement

### **Méthode 1 : Déploiement avec render.yaml (Recommandé)**

1. **Connectez-vous à Render**
   - Allez sur [render.com](https://render.com)
   - Connectez-vous avec GitHub

2. **Créez un nouveau Blueprint**
   - Cliquez sur **"New +"** → **"Blueprint"**
   - Sélectionnez votre repository GitHub
   - Render détectera automatiquement le fichier `render.yaml`

3. **Configurez les variables d'environnement**
   - `DATABASE_URL` : URL de votre base PostgreSQL Render (déjà configurée)
   - `SECRET_KEY` : Généré automatiquement
   - `SESSION_SECRET` : Généré automatiquement

4. **Déployez**
   - Cliquez sur **"Apply"**
   - Render créera automatiquement :
     - Le service web
     - La base de données PostgreSQL
     - Le disque pour les uploads

---

### **Méthode 2 : Déploiement Manuel**

Si vous préférez configurer manuellement :

#### **A. Créer la Base de Données**

1. Dans Render Dashboard → **"New +"** → **"PostgreSQL"**
2. Configurez :
   - **Name** : `etude-line-db`
   - **Database** : `etude_line`
   - **User** : `etude_line_admin`
   - **Region** : Oregon (ou votre région)
   - **Plan** : Free
3. Cliquez sur **"Create Database"**
4. Copiez l'**Internal Database URL**

#### **B. Créer le Service Web**

1. Dans Render Dashboard → **"New +"** → **"Web Service"**
2. Sélectionnez votre repository
3. Configurez :

**Build & Deploy**
```
Name: etude-line
Region: Oregon
Branch: main
Root Directory: (laissez vide)
Runtime: Python 3

Build Command:
pip install -r requirements.txt

Start Command:
gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --timeout 120
```

**Environment Variables**
```
PYTHON_VERSION = 3.11.2
DATABASE_URL = [collez l'URL de votre base de données]
SECRET_KEY = [générez une clé aléatoire]
SESSION_SECRET = [générez une clé aléatoire]
```

4. Cliquez sur **"Create Web Service"**

#### **C. Configurer le Disque (Important !)**

1. Dans votre service web → **"Disks"**
2. Cliquez sur **"Add Disk"**
3. Configurez :
   - **Name** : `uploads-disk`
   - **Mount Path** : `/opt/render/project/src/uploads`
   - **Size** : 1 GB
4. Cliquez sur **"Save"**

⚠️ **IMPORTANT** : Sans ce disque, vos fichiers uploadés seront perdus à chaque redéploiement !

---

## 🔧 Commandes de Déploiement

### **Start Command (Production)**
```bash
gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --timeout 120
```

### **Alternative (Simple)**
```bash
uvicorn main:app --host 0.0.0.0 --port $PORT
```

### **Build Command**
```bash
pip install -r requirements.txt
```

---

## 🎯 Points Clés

### ✅ **Ce qui est configuré automatiquement**

1. **Port dynamique** : L'app utilise `$PORT` de Render
2. **Environnement** : Détection automatique (production vs développement)
3. **Reload** : Désactivé en production, activé en local
4. **Workers** : 4 workers avec Gunicorn pour meilleures performances

### ⚠️ **À vérifier**

1. **Database URL** : Doit être l'URL interne de Render PostgreSQL
2. **Disque** : Configuré pour `/opt/render/project/src/uploads`
3. **Variables d'environnement** : SECRET_KEY et SESSION_SECRET définis

---

## 🐛 Dépannage

### **Erreur : "No open ports detected"**

**Solution** : Vérifiez que votre Start Command utilise `$PORT`
```bash
✅ Correct: --bind 0.0.0.0:$PORT
❌ Incorrect: --bind 0.0.0.0:5000
```

### **Erreur : L'app se déploie mais ne répond pas**

**Solutions** :
1. Vérifiez les logs Render
2. Vérifiez que `DATABASE_URL` est correcte
3. Vérifiez que le disque est monté sur `/opt/render/project/src/uploads`

### **Erreur : "Build failed"**

**Solutions** :
1. Vérifiez que `requirements.txt` n'a pas de doublons
2. Vérifiez que `PYTHON_VERSION=3.11.2` est défini
3. Vérifiez les logs de build dans Render

### **Les fichiers uploadés disparaissent**

**Solution** : Configurez le disque Render (voir section C ci-dessus)

---

## 📊 Configuration Optimale

### **Production (Recommandé)**
- **Workers** : 4
- **Worker Class** : uvicorn.workers.UvicornWorker
- **Timeout** : 120 secondes
- **Reload** : Désactivé
- **Disque** : 1 GB pour uploads

### **Plan Gratuit Render**
- 750 heures/mois
- 512 MB RAM
- Arrêt après 15 min d'inactivité
- Redémarrage automatique sur requête

---

## 🔗 Ressources

- [Documentation Render](https://render.com/docs)
- [Exemple FastAPI sur Render](https://github.com/render-examples/fastapi)
- [Documentation FastAPI Deployment](https://fastapi.tiangolo.com/deployment/)

---

## ✨ Résultat Final

Une fois déployé, votre application sera accessible à :
```
https://etude-line.onrender.com
```

🎉 **Votre plateforme éducative est maintenant en ligne !**
