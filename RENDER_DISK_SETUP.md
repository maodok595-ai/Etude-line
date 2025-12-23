# 📁 Configuration Render Disk pour fichiers uploads

## 🔴 Problème
Sur Render, le système de fichiers est **éphémère** - le dossier `uploads/` est supprimé à chaque redéploiement. Tous vos cours, exercices et solutions uploadés disparaissent.

## ✅ Solution : Render Disk
Render Disk est un stockage persistant qui survit aux redéploiements.

---

## 📋 Guide de configuration (5 minutes)

### Étape 1 : Accéder au Web Service
1. Allez sur **Render Dashboard** : https://dashboard.render.com
2. Cliquez sur votre **Web Service** (Étude LINE)

### Étape 2 : Créer le disque
1. Dans le menu de gauche, cliquez sur **"Disks"**
2. Cliquez sur **"Add Disk"**

### Étape 3 : Configurer le disque
Remplissez les champs suivants :

**Name** (Nom du disque) :
```
uploads-storage
```

**Mount Path** (Chemin de montage) :
```
/opt/render/project/src/uploads
```
⚠️ **IMPORTANT** : Copiez exactement ce chemin ! C'est l'emplacement du dossier uploads dans votre application.

**Size** (Taille) :
- Minimum : **1 GB** (recommandé pour commencer)
- Augmentez selon vos besoins (2-5 GB si vous avez beaucoup de contenu)

### Étape 4 : Sauvegarder
1. Cliquez sur **"Add Disk"**
2. Render va **redéployer automatiquement** votre application
3. Le disque sera monté au démarrage

---

## 🎯 Vérification

Après le redéploiement, vos fichiers seront maintenant **persistants** :

### ✅ Ce qui change
- ✅ Le dossier `uploads/` est maintenant sur un disque persistant
- ✅ Les fichiers **survivent** aux redéploiements
- ✅ Vous pouvez uploader des cours sans craindre de les perdre

### 📊 Structure finale
```
Render Web Service
├── Code (éphémère, recréé à chaque deploy)
│   ├── main.py
│   ├── models.py
│   └── ...
└── Disk: uploads-storage (PERSISTANT)
    └── uploads/
        ├── cours/
        ├── exercices/
        └── solutions/
```

---

## 💰 Coût

**Render Disk Pricing** :
- **$0.25 par GB/mois**
- Exemple : 1 GB = $0.25/mois (~250 FCFA/mois)
- Exemple : 5 GB = $1.25/mois (~1250 FCFA/mois)

C'est très abordable comparé à la base PostgreSQL que vous payez déjà.

---

## 🔧 Dépannage

### Problème : Le dossier uploads reste vide après configuration
**Solution** :
1. Vérifiez que le Mount Path est exactement : `/opt/render/project/src/uploads`
2. Redéployez manuellement : **Manual Deploy** → **Deploy latest commit**
3. Attendez que le déploiement soit complet

### Problème : Erreur "Permission denied" dans les logs
**Solution** :
- Render configure automatiquement les permissions
- Si le problème persiste, contactez le support Render

### Problème : Les anciens fichiers ont disparu
**Cause** : Les fichiers uploadés AVANT la configuration du disque étaient sur le système éphémère.
**Solution** : Vous devrez les re-uploader une fois le disque configuré.

---

## 📝 Notes importantes

1. **Le disque est créé vide** la première fois
   - Vous devrez re-uploader les fichiers qui étaient là avant
   
2. **Le disque est lié à ce Web Service uniquement**
   - Si vous supprimez le Web Service, le disque est supprimé aussi
   
3. **Sauvegarde recommandée**
   - Pensez à télécharger régulièrement vos fichiers importants
   - Ou configurez des snapshots sur Render (option payante)

4. **Augmentation de taille**
   - Vous pouvez augmenter la taille du disque à tout moment
   - ⚠️ Vous ne pouvez PAS réduire la taille une fois augmentée

---

## ✅ Résultat final

Une fois configuré :
- ✅ Vos données PostgreSQL sont persistantes (déjà fait)
- ✅ Vos fichiers uploads sont persistants (après configuration disque)
- ✅ Plus de perte de données lors des redéploiements !

Vous aurez une application complètement fiable et professionnelle ! 🚀
