# 🚀 Guide de Déploiement sur Render

## ⚠️ PROBLÈME : Vos données disparaissent après chaque redéploiement ?

### 🔍 Cause du problème
Votre application se connecte à une **mauvaise base de données** qui n'est pas persistante sur Render.

## ✅ SOLUTION : Configurer la base de données PostgreSQL externe

### Étape 1 : Vérifier votre base PostgreSQL sur Render

1. Allez sur votre **Dashboard Render** : https://dashboard.render.com
2. Trouvez votre **base de données PostgreSQL** (celle que vous payez)
3. Cliquez dessus pour voir les détails
4. Copiez l'**URL de connexion externe** (External Database URL)
   - Elle ressemble à : `postgresql://user:password@host.render.com/dbname`

### Étape 2 : Configurer la variable d'environnement sur votre Web Service

1. Toujours sur Render Dashboard, allez sur votre **Web Service** (l'application Étude LINE)
2. Cliquez sur **"Environment"** dans le menu de gauche
3. Cherchez la variable `EXTERNAL_DATABASE_URL`

#### Si `EXTERNAL_DATABASE_URL` existe déjà :
- Vérifiez qu'elle contient bien l'URL PostgreSQL de l'Étape 1
- Si elle est vide ou incorrecte, collez la bonne URL

#### Si `EXTERNAL_DATABASE_URL` n'existe PAS :
1. Cliquez sur **"Add Environment Variable"**
2. Nom : `EXTERNAL_DATABASE_URL`
3. Valeur : Collez l'URL PostgreSQL de l'Étape 1
4. Cliquez sur **"Save Changes"**

### Étape 3 : Redéployer l'application

1. Render va redéployer automatiquement après avoir sauvegardé
2. **OU** cliquez manuellement sur **"Manual Deploy"** > **"Deploy latest commit"**

### Étape 4 : Vérifier que ça fonctionne

Après le redéploiement, regardez les **logs de démarrage** :

✅ **CORRECT** - Vous devriez voir :
```
======================================================================
🔵 CONNEXION À LA BASE DE DONNÉES EXTERNE (RENDER POSTGRESQL)
   Host: [votre-host].render.com
   ⚠️  ATTENTION : Vos données sont sur cette base - NE PAS LA SUPPRIMER
======================================================================
```

❌ **INCORRECT** - Si vous voyez ceci, c'est le problème :
```
======================================================================
⚠️  CONNEXION À LA BASE DE DONNÉES REPLIT (LOCALE)
   PROBLÈME : Cette base n'est PAS persistante sur Render !
   SOLUTION : Configurez EXTERNAL_DATABASE_URL sur Render
======================================================================
```

## 🎯 Résultat final

Une fois configuré correctement :
- ✅ Vos données (professeurs, étudiants, chapitres) sont **permanentes**
- ✅ Les redéploiements **ne suppriment plus rien**
- ✅ Vos fichiers uploadés restent dans le dossier `uploads/`
- ✅ La migration ne se relance plus inutilement

## 🔒 Sécurité importante

**NE JAMAIS** :
- ❌ Supprimer votre base PostgreSQL Render
- ❌ Partager l'URL de connexion publiquement
- ❌ Commit l'URL dans Git (utilisez toujours les variables d'environnement)

## 📞 Besoin d'aide ?

Si vos données disparaissent toujours :
1. Vérifiez les logs de démarrage de Render
2. Assurez-vous que `EXTERNAL_DATABASE_URL` est bien configurée
3. Vérifiez que votre base PostgreSQL Render est active (pas suspendue)

## 🔑 Variables d'environnement requises sur Render

```
EXTERNAL_DATABASE_URL=postgresql://user:password@host.render.com/dbname
SECRET_KEY=votre-clé-secrète-unique
SESSION_SECRET=votre-secret-de-session
```

Votre application va automatiquement utiliser `EXTERNAL_DATABASE_URL` si elle existe, sinon elle tombera sur `DATABASE_URL` (qui est temporaire).
