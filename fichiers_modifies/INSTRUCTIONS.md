# 📝 Instructions pour mettre à jour GitHub

## Fichiers modifiés dans ce dossier :

1. **templates/dashboard_admin.html** - Correction du bouton de fermeture des formulaires
2. **static/sw.js** - Mise à jour du cache PWA v4 → v5

## 🔧 Modifications apportées :

### 1. dashboard_admin.html
- ✅ Ajout de `type="button"` aux boutons de fermeture (✕)
- ✅ Amélioration de la fonction JavaScript `toggleForm()`
- ✅ Correction pour tous les formulaires (admin, prof, université, UFR, filière, matière)

### 2. sw.js (Service Worker)
- ✅ Mise à jour de la version du cache : v4 → v5
- ✅ Force la mise à jour du cache PWA pour tous les utilisateurs

## 📤 Comment mettre à jour votre dépôt GitHub :

### Sur votre ordinateur local :

```bash
# 1. Cloner ou mettre à jour votre dépôt
cd Etude-line
git pull origin main

# 2. Copier les fichiers de ce dossier vers votre dépôt
# - Copiez templates/dashboard_admin.html vers votre dossier templates/
# - Copiez static/sw.js vers votre dossier static/

# 3. Commit et push
git add templates/dashboard_admin.html static/sw.js
git commit -m "Correction bouton fermeture + mise à jour cache PWA v5"
git push origin main
```

## 🚀 Après le push sur GitHub :

1. Sur **Render** : Manual Deploy → Deploy latest commit
2. Attendez le déploiement
3. **Videz le cache du Service Worker** dans votre navigateur :
   - Chrome/Edge : DevTools (F12) → Application → Service Workers → Unregister
   - Ou faites : Ctrl + Shift + R (hard refresh)

## ✅ Test final :

1. Connectez-vous au dashboard admin
2. Cliquez sur "➕ Créer un administrateur"
3. Le formulaire s'ouvre
4. Cliquez sur la croix (✕) en haut à droite
5. Le formulaire doit se fermer et afficher la liste

---

**Note:** Le bouton de fermeture fonctionne maintenant grâce à deux corrections :
- `type="button"` empêche la soumission du formulaire
- La fonction JavaScript vérifie correctement l'état visible/caché du formulaire
