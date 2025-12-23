# 🔧 Solution : Logos qui disparaissent sur Render

## ❌ Problème
Vous avez uploadé des logos d'universités, mais ils **disparaissent après chaque redéploiement sur Render**.

## ✅ Cause
Render utilise un **système de fichiers éphémère** par défaut. À chaque redéploiement :
- Votre code est recompilé
- Le dossier `uploads/` est recréé **vide**
- Tous vos fichiers uploadés sont **perdus**

## 🎯 Solution : Render Disk (Stockage persistant)

J'ai déjà modifié le code pour qu'il **détecte automatiquement** l'environnement et utilise le bon chemin de stockage :

- **En développement (Replit)** : `uploads/` (local)
- **En production (Render)** : `/opt/render/project/src/uploads` (Render Disk)

### ✅ Vous verrez maintenant ces messages dans les logs Render :
```
📁 Environnement: RENDER (production)
💾 Stockage: Render Disk → /opt/render/project/src/uploads
```

---

## 📋 Étapes pour configurer le Render Disk

### 1️⃣ Se connecter à Render
- Allez sur : **https://dashboard.render.com**
- Connectez-vous à votre compte
- Cliquez sur votre **Web Service** (Étude LINE)

### 2️⃣ Créer le disque
- Dans le menu de gauche, cliquez sur **"Disks"**
- Cliquez sur le bouton bleu **"Add Disk"**

### 3️⃣ Configurer le disque
Remplissez les champs suivants **exactement** :

| Champ | Valeur |
|-------|--------|
| **Name** | `uploads-storage` |
| **Mount Path** | `/opt/render/project/src/uploads` |
| **Size** | `1 GB` (minimum) ou plus selon vos besoins |

⚠️ **IMPORTANT** : Le **Mount Path** doit être exactement : `/opt/render/project/src/uploads`

### 4️⃣ Sauvegarder
- Cliquez sur **"Add Disk"**
- Render va **redéployer automatiquement** votre application (3-5 minutes)
- Attendez que le déploiement soit complet (statut : **Live**)

---

## 🧪 Vérification

### Option 1 : Vérifier dans les logs Render
1. Allez dans **"Logs"** de votre Web Service
2. Cherchez les lignes suivantes au démarrage :
```
📁 Environnement: RENDER (production)
💾 Stockage: Render Disk → /opt/render/project/src/uploads
```

Si vous voyez ces lignes, **le disque est correctement monté** ! ✅

### Option 2 : Tester un upload
1. Connectez-vous en tant qu'administrateur
2. Uploadez un logo d'université
3. Redéployez manuellement (Manual Deploy → Deploy latest commit)
4. Vérifiez que le logo est **toujours là** après le redéploiement

---

## 💰 Coût du Render Disk

| Taille | Coût mensuel |
|--------|--------------|
| 1 GB | $0.25/mois (~250 FCFA) |
| 5 GB | $1.25/mois (~1,250 FCFA) |
| 10 GB | $2.50/mois (~2,500 FCFA) |

**Recommandation** : Commencez avec **1 GB**, vous pourrez toujours augmenter plus tard.

---

## ⚠️ Points importants

### 1. Les anciens fichiers sont perdus
- Les logos uploadés **avant** la configuration du disque étaient sur le système éphémère
- Vous devrez les **re-uploader une fois** après avoir configuré le disque

### 2. Le disque commence vide
- Render crée un disque vide la première fois
- Re-uploadez vos logos après la configuration

### 3. Augmentation de taille uniquement
- Vous pouvez **augmenter** la taille du disque à tout moment
- ⚠️ Vous **ne pouvez PAS réduire** la taille une fois augmentée

---

## 🔧 Dépannage

### Problème : Le disque semble ne pas fonctionner

**Solution 1 - Vérifier le Mount Path** :
1. Allez dans **Disks** sur Render
2. Vérifiez que le **Mount Path** est exactement : `/opt/render/project/src/uploads`
3. Si ce n'est pas le cas, supprimez le disque et recréez-le avec le bon chemin

**Solution 2 - Forcer un redéploiement** :
1. Allez dans l'onglet **"Manual Deploy"**
2. Cliquez sur **"Deploy latest commit"**
3. Attendez que le déploiement soit terminé

**Solution 3 - Vérifier les logs** :
1. Allez dans **"Logs"**
2. Cherchez les erreurs liées au disque
3. Vérifiez que vous voyez le message de détection du Render Disk

---

## ✅ Résultat final

Une fois configuré, votre application aura :
- ✅ **Base de données PostgreSQL persistante** (déjà configurée)
- ✅ **Fichiers uploads persistants** (après configuration du Render Disk)
- ✅ **Plus de perte de données** lors des redéploiements

🎉 Votre application sera **100% fiable et professionnelle** !

---

## 📞 Besoin d'aide ?

Si vous rencontrez des problèmes :
1. Vérifiez que le Mount Path est correct : `/opt/render/project/src/uploads`
2. Consultez les logs Render pour voir les messages de diagnostic
3. Contactez le support Render si nécessaire

**Documentation Render Disk** : https://docs.render.com/disks
