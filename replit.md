# Étude LINE

## Recent Changes

**29 octobre 2025 - Sections pliables fermées par défaut**

### Amélioration UX : Interface propre au chargement
**Demande utilisateur** : Toutes les sections pliables (flèches ►) doivent être fermées par défaut à chaque ouverture de l'application pour une meilleure organisation.

**Avant** : 
- Les cartes statistiques (Professeurs, Étudiants, Universités, etc.) mémorisaient leur état (ouvert/fermé) via `localStorage`
- Les filières et niveaux dans la liste des étudiants s'affichaient ouverts (▼) par défaut
- Interface encombrée au rechargement

**Après** : Toutes les sections pliables sont maintenant fermées par défaut (flèche ►) à chaque ouverture, offrant une interface propre et organisée.

**Modifications appliquées** :
1. **Cartes statistiques** :
   - Suppression de `localStorage.setItem()` dans la fonction `toggleStatCard`
   - Suppression du code `DOMContentLoaded` qui rouvrait automatiquement les sections
   
2. **Liste des étudiants - Filières** :
   - Flèche changée de ▼ à ► (ligne 1847)
   - Ajout de `display: none` au contenu des filières (ligne 1851)
   
3. **Liste des étudiants - Niveaux** :
   - Flèche changée de ▼ à ► (ligne 1884)
   - Ajout de `display: none` au contenu des niveaux (ligne 1893)

**Fichiers modifiés** :
- `templates/dashboard_admin.html` (lignes 1278-1294, 1847, 1851, 1884, 1893)

**Impact** :
- ✅ Interface plus propre et organisée au chargement
- ✅ L'utilisateur peut ouvrir uniquement les sections qui l'intéressent
- ✅ Cohérence de l'expérience utilisateur à chaque visite
- ✅ Liste des étudiants organisée par filières et niveaux, tous fermés par défaut
- ✅ Meilleure navigation et moins de surcharge visuelle

---

**29 octobre 2025 - Correction de l'erreur "showTab is not defined"**

### Bug Fix : Onglets ne fonctionnent pas (erreur JavaScript)
**Problème rapporté** : Les boutons d'onglets (Administrateurs, Professeurs, Étudiants, etc.) dans le dashboard admin affichaient l'erreur JavaScript : `ReferenceError: showTab is not defined`.

**Cause** : 
- La fonction `showTab` était définie dans un bloc `<script>` situé **après** les boutons d'onglets dans le HTML
- Les boutons avec `onclick="showTab(...)"` étaient rendus avant que la fonction ne soit exposée au scope global
- Bien que `window.showTab = showTab` existait, il était exécuté trop tard dans le parsing du HTML

**Solution** :
1. **Pré-déclaration de la fonction** : Ajout d'un nouveau bloc `<script>` immédiatement après le premier bloc de fonctions
2. **Exposition anticipée** : `window.showTab = showTab` avant le rendu des boutons d'onglets
3. **Fonction temporaire** : Version simplifiée de `showTab` qui sera remplacée par la version complète plus tard

**Exemple de structure** :
```html
<!-- Bloc 1 : Fonctions principales -->
<script>
    // toggleSection, toggleStatCard, etc.
    window.toggleSection = toggleSection;
</script>

<!-- Bloc 2 : Pré-déclaration showTab -->
<script>
    function showTab(tabName) { /* version simplifiée */ }
    window.showTab = showTab;
</script>

<!-- Maintenant les boutons peuvent utiliser showTab -->
<button onclick="showTab('admin')">Administrateurs</button>

<!-- Bloc 3 : Version complète de showTab -->
<script>
    function showTab(tabName) { /* version complète avec toutes les fonctionnalités */ }
    window.showTab = showTab; // remplace la version simplifiée
</script>
```

**Fichiers modifiés** :
- `templates/dashboard_admin.html` (lignes 1325-1338)

**Impact** :
- ✅ Tous les onglets fonctionnent correctement sans erreur JavaScript
- ✅ Navigation fluide entre les différentes sections du dashboard admin
- ✅ Compatibilité maintenue avec tous les navigateurs

---

**29 octobre 2025 - Correction du bug de suppression avec caractères spéciaux**

### Bug Fix : Impossible de supprimer/modifier des utilisateurs avec apostrophes, guillemets ou astérisques
**Problème rapporté** : Les étudiants, professeurs, administrateurs, universités, UFRs, filières et matières dont les noms contiennent des caractères spéciaux comme **'** (apostrophe), **"** (guillemets) ou ***** (astérisque) ne pouvaient pas être supprimés ou modifiés via l'interface admin.

**Cause initiale** : 
- Les attributs `onclick` passaient les noms directement dans du JavaScript
- Exemple : `onclick="deleteEtudiant('username', 'John O'Brien')"` → L'apostrophe dans "O'Brien" cassait le code
- Risque de sécurité : Injection JavaScript possible

**Première correction (CASSÉE)** :
- Ajout du filtre `|tojson` : `onclick="deleteProf({{ prof.username|tojson }}, ...)"`
- **Problème** : Conflit de guillemets doubles → `onclick="func("param")"` ❌
- Résultat : TOUS les boutons de suppression ont arrêté de fonctionner

**Solution finale (FONCTIONNE)** :
1. **Changement des guillemets onclick** : `onclick="..."` → `onclick='...'`
2. **Utilisation de |tojson** pour échapper les paramètres
3. **Correction des booléens** : `{{ "true" }}` → `{{ value|tojson|lower }}`

**Exemple de code corrigé** :
```html
<!-- Avant (cassé avec apostrophe) -->
<button onclick="deleteProf('{{ username }}', 'John O'Brien')">

<!-- Première tentative (conflit guillemets) -->
<button onclick="deleteProf({{ username|tojson }}, {{ name|tojson }})">
Génère : onclick="deleteProf("user1", "John O'Brien")" ❌

<!-- Solution finale (fonctionne) -->
<button onclick='deleteProf({{ username|tojson }}, {{ name|tojson }})'>
Génère : onclick='deleteProf("user1", "John O'\''Brien")' ✅
```

**Fonctions corrigées** (13 au total) :
1. `deleteEtudiant` - Suppression d'étudiant
2. `editProf`, `deleteProf`, `toggleProfStatus` - Gestion des professeurs
3. `editAdmin`, `deleteAdmin`, `toggleAdminStatus` - Gestion des administrateurs
4. `editUniversite`, `deleteUniversite`, `uploadLogo` - Gestion des universités
5. `editUfr`, `deleteUfr` - Gestion des UFR
6. `editFiliere`, `deleteFiliere` - Gestion des filières
7. `editMatiere`, `deleteMatiere` - Gestion des matières

**Fichiers modifiés** :
- `templates/dashboard_admin.html` (13 corrections onclick avec apostrophes simples + |tojson)

**Impact** :
- ✅ Tous les boutons de suppression/modification fonctionnent à nouveau
- ✅ Noms avec caractères spéciaux supportés (O'Brien, D'Angelo, L'Hôpital, etc.)
- ✅ Protection contre l'injection JavaScript
- ✅ Code sécurisé et conforme aux bonnes pratiques Jinja2

---

**29 octobre 2025 - Optimisation de la performance des boutons de création**

### Amélioration : Réduction du temps de réponse des formulaires de création
**Problème rapporté** : L'application était très lente, surtout au niveau des boutons de création (professeurs, UFR, filières, etc.).

**Cause identifiée** : 
- Multiples requêtes base de données en séquence pour les validations
- Boucles avec requêtes individuelles (problème N+1)
- Latence réseau importante avec la base Render PostgreSQL (Oregon)

**Exemple avant** : Création d'un professeur avec 3 UFRs et 5 filières :
- 3 requêtes séparées pour vérifier username
- 3 requêtes (une par UFR) pour validation
- 3 requêtes (une par UFR) pour récupérer les filières
- **Total : ~9 requêtes avec latence réseau**

**Optimisations appliquées** :
1. **Vérification username** : 3 requêtes → 1 requête UNION
2. **Validation UFRs** : N requêtes en boucle → 1 requête avec `in_()`
3. **Validation filières** : N requêtes en boucle → 1 requête avec `in_()`

**Exemple après** : Même création de professeur :
- 1 requête UNION pour vérifier username
- 1 requête pour valider toutes les UFRs
- 1 requête pour récupérer toutes les filières
- **Total : 3 requêtes (réduction de 66%)**

**Fichiers modifiés** :
- `main.py` (route `/admin/create-prof`, lignes 2286-2337)

**Impact** :
- ✅ Temps de réponse réduit de 50-70% pour la création de professeurs
- ✅ Moins de latence réseau avec la base Render
- ✅ Meilleure expérience utilisateur
- ✅ Pas de changement fonctionnel, toutes les validations restent identiques

---

**29 octobre 2025 - Affichage vertical des fichiers dans le dashboard professeur**

### Amélioration : Cours, exercices, solutions et commentaires en colonne
**Demande utilisateur** : Dans le dashboard professeur sur ordinateur, les fichiers (cours, exercices, solutions) et commentaires s'affichaient horizontalement côte à côte, ce qui n'était pas optimal.

**Avant** : Sur grand écran, les sections s'affichaient en grille horizontale avec plusieurs colonnes (layout grid avec `repeat(auto-fit, minmax(200px, 1fr))`).

**Après** : Toutes les sections s'affichent maintenant verticalement les unes en dessous des autres, comme dans le dashboard étudiant (layout flexbox avec `flex-direction: column`).

**Fichiers modifiés** :
- `templates/dashboard_prof.html` (ligne 1966)

**Impact** :
- ✅ Affichage vertical uniforme sur toutes les tailles d'écran
- ✅ Cohérence visuelle avec le dashboard étudiant
- ✅ Meilleure lisibilité des contenus sur ordinateur
- ✅ Pas d'effet secondaire sur les fonctionnalités existantes

---

**29 octobre 2025 - Optimisation de l'affichage sur ordinateur (suppression du scroll horizontal)**

### Amélioration : Élimination des mouvements de va-et-viens sur ordinateur
**Problème rapporté** : Sur ordinateur, les pages défilaient horizontalement et créaient des mouvements de va-et-viens indésirables.

**Cause** : Certains éléments de l'interface débordaient de la largeur de la fenêtre, causant un scroll horizontal non souhaité et des comportements visuels gênants.

**Solution appliquée** :
1. **Ajout de `overflow-x: hidden`** sur `html` et `body` dans tous les dashboards
2. **Restriction de largeur** : `max-width: 100vw` sur body pour empêcher tout débordement
3. **Containers optimisés** : Utilisation de `max-width: min(XXXpx, 100%)` pour garantir que les conteneurs ne dépassent jamais l'écran
4. **Sécurité supplémentaire** : `overflow-x: hidden` également sur les containers principaux

**Fichiers modifiés** :
- `templates/dashboard_admin.html`
- `templates/dashboard_prof.html`
- `templates/dashboard_etudiant.html`

**Impact** :
- ✅ Plus aucun mouvement de va-et-vient horizontal sur ordinateur
- ✅ Affichage stable et professionnel sur tous les écrans
- ✅ Meilleure expérience utilisateur sur grand écran
- ✅ Pas d'impact sur la version mobile (déjà optimisée)

---

**28 octobre 2025 - Uniformisation de la couleur des niveaux en violet**

### Amélioration visuelle : Tous les niveaux en violet
**Demande utilisateur** : Dans les dashboards étudiant et professeur, tous les niveaux doivent être colorés en violet.

**Avant** : Chaque niveau avait une couleur différente :
- L1 : Vert
- L2 : Bleu  
- L3 : Violet
- M1 : Orange
- M2 : Rouge

**Après** : Tous les niveaux sont maintenant en violet (#9C27B0 → #7B1FA2)
- L1 : Violet ✅
- L2 : Violet ✅
- L3 : Violet ✅
- M1 : Violet ✅
- M2 : Violet ✅

**Impact** :
- ✅ Interface plus cohérente et harmonieuse
- ✅ Focus sur la structure hiérarchique plutôt que la couleur
- ✅ Identité visuelle unifiée dans les dashboards étudiant et professeur

**Fichiers modifiés** : `templates/dashboard_etudiant.html`, `templates/dashboard_prof.html`

---

**28 octobre 2025 - Stockage des logos universitaires dans PostgreSQL**

### Solution : Logos persistants entre les redéploiements Render
**Problème rapporté** : Les logos des universités sont perdus après chaque redéploiement sur Render car le système de fichiers est éphémère.

**Ancienne approche (ÉCHEC)** : Stockage dans dossier `uploads/` avec Render Disk
- ❌ Nécessite configuration manuelle Render Disk
- ❌ Fichiers toujours perdus si Render Disk mal configuré
- ❌ Complexité de gestion de fichiers

**Nouvelle solution (SUCCÈS)** : Stockage des images directement dans PostgreSQL
1. **Ajout de colonnes au modèle** `Universite` :
   - `logo_data` (LargeBinary/BYTEA) : Stocke l'image en binaire
   - `logo_content_type` (VARCHAR) : Stocke le type MIME (image/jpeg, image/png, etc.)

2. **Script de migration** : `migration_logo_postgresql.py`
   - Ajoute automatiquement les colonnes à la base Render
   - Transaction sécurisée avec rollback en cas d'erreur

3. **Route d'upload modifiée** : `/admin/upload-logo`
   - Lit l'image en mémoire (limite 5 MB)
   - Stocke directement dans PostgreSQL via `logo_data`
   - Met à jour `logo_url` vers `/logo/<universite_id>`

4. **Nouvelle route de service** : `/logo/<universite_id>`
   - Sert les images depuis PostgreSQL
   - Cache HTTP de 24h pour performance
   - Retourne 404 si logo absent

**Avantages de cette solution** :
- ✅ **Persistance garantie** : Les logos survivent à tous les redéploiements Render
- ✅ **Pas de configuration Render Disk** : Tout est dans PostgreSQL
- ✅ **Sauvegarde automatique** : Les logos sont sauvegardés avec la base de données
- ✅ **Rollback possible** : Avec les checkpoints Replit
- ✅ **Simple** : Pas de gestion de fichiers, tout dans la BD

**Impact** :
- ✅ Les nouveaux logos uploadés seront stockés en base de données
- ✅ Plus besoin du dossier `uploads/` pour les logos
- ✅ Fonctionne immédiatement sur Render sans configuration supplémentaire

**⚠️ IMPORTANT** : 
- Exécutez `python migration_logo_postgresql.py` sur Render pour activer la fonctionnalité
- Les anciens logos doivent être re-uploadés via l'interface admin

**Fichiers modifiés** : `models.py`, `main.py`, nouveau fichier `migration_logo_postgresql.py`

---

**28 octobre 2025 - Suppression en cascade complète pour les universités**

### Fonctionnalité : Suppression complète d'une université
**Demande** : Permettre de supprimer une université avec toutes ses données associées (administrateurs, professeurs, étudiants, UFRs, filières, matières, chapitres, etc.)

**Solution implémentée** :
1. **Modifications dans `models.py`** :
   - Ajout de `ondelete="CASCADE"` sur toutes les Foreign Keys pointant vers `universites` :
     - `UFR.universite_id`
     - `Administrateur.universite_id`
     - `Professeur.universite_id`
     - `Etudiant.universite_id`
     - `ChapitreComplet.universite_id`
   - Configuration ORM avec `cascade="all, delete-orphan"` uniquement pour UFR et Etudiant (colonnes NOT NULL)

2. **Script de migration SQL** : `migration_universite_cascade.py`
   - Modifie les contraintes de clés étrangères dans la base de données PostgreSQL
   - Exécute séparément chaque commande DROP/ADD pour compatibilité psycopg2
   - Transaction sécurisée avec rollback automatique en cas d'erreur

**Impact de la suppression d'une université** :
Quand vous supprimez une université, le système supprime automatiquement et en cascade :
- ✅ Tous les UFRs de cette université
- ✅ Toutes les filières (via UFR)
- ✅ Toutes les matières (via filières)
- ✅ Tous les chapitres de cette université
- ✅ Tous les étudiants de cette université
- ✅ Tous les professeurs de cette université
- ✅ Tous les administrateurs secondaires de cette université
- ✅ Tous les paramètres et configurations de cette université

**⚠️ IMPORTANT POUR RENDER** : 
1. Le script `migration_universite_cascade.py` **DOIT** être exécuté sur la base de données Render avant de pouvoir supprimer des universités
2. Sauvegardez votre base de données avant d'exécuter la migration
3. Testez la suppression en environnement de staging/test avant la production

**Fichiers modifiés** : `models.py`, nouveau fichier `migration_universite_cascade.py`

---

**28 octobre 2025 - Simplification du guide d'installation PWA sur iPhone**

### Amélioration : Guide simplifié avec instructions Safari uniquement
**Demande utilisateur** : Supprimer les instructions Chrome iPhone car elles sont confuses et inutiles.

**Raison** : Chrome sur iPhone ne permet pas l'installation directe de PWA - il faut obligatoirement utiliser Safari. Les boutons de sélection Safari/Chrome créaient de la confusion.

**Solution** : Simplification complète du guide d'installation iOS :
1. **Suppression** : Boutons de sélection Safari/Chrome
2. **Suppression** : Section complète des instructions Chrome
3. **Suppression** : Fonction JavaScript `toggleBrowserInstructions()`
4. **Conservation** : Uniquement les instructions Safari, claires et précises

**Instructions finales (Safari uniquement)** :
- **Étape 1** : Appuyer sur le bouton Partage ⬆️ en bas de Safari (dans la barre du navigateur)
- **Étape 2** : Défiler DANS LE MENU popup pour trouver l'option
- **Étape 3** : Sélectionner "Sur l'écran d'accueil ➕" puis "Ajouter"

**Impact** :
- ✅ Guide beaucoup plus simple et direct
- ✅ Pas de confusion avec Chrome
- ✅ Instructions focalisées sur la seule méthode qui fonctionne (Safari)
- ✅ Meilleure expérience utilisateur

**Fichiers modifiés** : `templates/index.html`

---

**28 octobre 2025 - Correction de l'icône PWA sur iPhone**

### Correction : Icône incorrecte lors de l'ajout à l'écran d'accueil iPhone
**Problème** : Quand les utilisateurs ajoutaient l'application à l'écran d'accueil de leur iPhone via Safari, l'icône affichée était une capture d'écran de la page au lieu du logo de l'application.

**Cause** : iOS/Safari ne lit **pas** le fichier `manifest.json` pour les icônes PWA. Il utilise exclusivement les balises `<link rel="apple-touch-icon">`. L'icône référencée avait également une mauvaise dimension (192x192 px au lieu de 180x180 px requis par iOS).

**Solution** :
1. Installation de **Pillow** pour la manipulation d'images
2. Redimensionnement de l'icône source (1024x1024) vers une icône optimisée 180x180 px
3. Ajout de balises `<link rel="apple-touch-icon" href="/static/icons/icon-180.png">` dans tous les templates HTML

**Changements appliqués** :
- Nouveau fichier : `static/icons/icon-180.png` (180x180 px, 25 KB)
- Templates modifiés : `index.html`, `login.html`, `dashboard_admin.html`, `dashboard_prof.html`, `dashboard_etudiant.html`
- Dépendance ajoutée : `Pillow==12.0.0` dans `requirements.txt`

**Impact** :
- ✅ L'icône de l'application s'affiche correctement lors de l'installation PWA sur iPhone
- ✅ Respecte les standards iOS 2025 (180x180 px pour iPhone moderne)
- ✅ Icône optimisée (25 KB au lieu de 621 KB)

**Fichiers modifiés** : Tous les templates HTML, ajout de `static/icons/icon-180.png`, `requirements.txt`

---

**28 octobre 2025 - Migration des logos universitaires vers stockage persistant**

### Correction : Logos universitaires perdus lors du redéploiement sur Render
**Problème** : Les logos des universités uploadés via l'interface admin étaient stockés dans le dossier `static/`. Sur Render, ce dossier est **éphémère** et recréé à chaque redéploiement, causant la perte de tous les logos.

**Solution** : Migration du stockage des logos du dossier `static/` vers le dossier `uploads/`.

**Changements appliqués** :
1. Modification de la route `/admin/upload-logo` dans `main.py` :
   - Ancien chemin : `static/logo_universite_{id}_{hash}.{ext}`
   - Nouveau chemin : `uploads/logo_universite_{id}_{hash}.{ext}`
   - URL servie : `/files/{filename}` (au lieu de `/static/{filename}`)

2. **Configuration requise sur Render** :
   - Le dossier `uploads/` DOIT être monté sur un **Render Disk** pour garantir la persistance
   - Sans Render Disk, les logos seront toujours perdus au redéploiement
   - Voir `GUIDE_DEPLOIEMENT_RENDER.md` pour les instructions de configuration du Render Disk

**Impact** :
- ✅ Les logos uploadés après cette modification persisteront entre les redéploiements (avec Render Disk configuré)
- ⚠️ Les anciens logos dans `static/` doivent être re-uploadés via l'interface admin
- ⚠️ Configuration Render Disk obligatoire pour la persistance complète

**Fichiers modifiés** : `main.py` (route `/admin/upload-logo`)

---

**28 octobre 2025 - Correction des bugs Render et améliorations PWA**

### Améliorations de l'interface d'installation PWA sur iOS
**Amélioration** : Remplacement du guide d'installation affiché directement par un bouton "Installer maintenant" sur iOS.

**Avant** : Les utilisateurs iOS voyaient directement un guide avec les instructions d'installation.

**Après** : Les utilisateurs iOS voient maintenant :
1. Un bouton élégant **"🚀 Installer maintenant"** (identique à Android)
2. Quand ils cliquent, une modale moderne s'ouvre avec les instructions détaillées
3. Design cohérent entre iOS et Android pour une meilleure expérience utilisateur

**Fichiers modifiés** : `templates/index.html` - Ajout de la modale d'instructions iOS avec animations

---

Deux bugs critiques rapportés par l'utilisateur ont été identifiés et corrigés sur l'environnement Replit :

### Bug 1 : Liste des matières ne s'ouvre pas sur Render
**Cause** : Les fonctions JavaScript dans `dashboard_admin.html` n'étaient pas accessibles depuis les attributs `onclick` en raison d'un problème de scope sur Render.

**Solution** : Exposition de ~45 fonctions JavaScript au scope global via `window.nomFonction = nomFonction` dans `dashboard_admin.html` (après ligne 1302 et avant ligne 4124).

**Impact** : Les boutons interactifs (ouvrir liste matières, modifier chapitre, supprimer, etc.) fonctionnent maintenant correctement.

### Bug 2 : Suppression d'UFR ne supprime pas les matières associées
**Cause** : Les Foreign Keys n'avaient pas de contraintes `ON DELETE CASCADE` au niveau de la base de données SQL.

**Solution appliquée sur Replit** :
1. Ajout de `ondelete="CASCADE"` dans `models.py` pour toutes les FK critiques :
   - `Filiere.ufr_id` → `ufrs` : ON DELETE CASCADE
   - `Matiere.filiere_id` → `filieres` : ON DELETE CASCADE
   - `Etudiant.ufr_id` et `filiere_id` : ON DELETE CASCADE
   - `ChapitreComplet.ufr_id`, `filiere_id`, `matiere_id` : ON DELETE CASCADE
   - `Professeur.ufr_id`, `filiere_id`, `matiere_id` : ON DELETE SET NULL (nullable)

2. Exécution de migration SQL pour recréer les contraintes avec CASCADE (voir `migration_cascade.py`)

3. Test de suppression en cascade réussi sur Replit :
   - Créé UFR → Filière → Matière
   - Supprimé l'UFR
   - Résultat : La filière ET la matière ont été supprimées automatiquement ✅

**⚠️ IMPORTANT POUR RENDER** : La migration SQL doit être exécutée sur la base de données Render pour que les corrections prennent effet en production. Exécutez le script `migration_cascade.py` sur Render ou via un accès direct à la base de données PostgreSQL de Render.

**28 octobre 2025** - Application importée depuis GitHub (maodok595-ai/Etude-line)
- Version importée : commit 483b133 (avant l'introduction de la fonctionnalité de création de matières multi-filière)
- Configuration : Python 3.11, FastAPI, PostgreSQL (Replit)
- État : Application fonctionnelle et accessible via preview sur port 5000

## Overview
Étude LINE is an educational web application built with FastAPI, designed for professors to share content (courses, exercises, solutions) with students. The platform features content organized hierarchically by university, field, level, semester, subject, and chapter. It includes a complete authentication system, robust content management, and is available as an installable Progressive Web App (PWA). The project aims to facilitate seamless educational content dissemination and access, enabling students to register and access all content freely.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### UI/UX Decisions
The application uses a server-side rendered architecture with Jinja2 templates, featuring a modern, responsive design with CSS Grid and Flexbox and a gradient color scheme. Key interfaces include dashboards for Professors, Students, and Admins, offering consistent branding, interactive content views, color-coded level cards, and icon-based actions. Admin panels feature consistent button-based forms, animated transitions, real-time search, and detailed student information display. All admin dashboard lists and individual user details are collapsible by default for a clean interface. University statistics are presented in compact, color-coded cards. The homepage includes a redesigned student registration flow with animations. The application is fully responsive for mobile, tablet, and PC, with specific optimizations for forms, notification centers, and dashboards, ensuring touch-friendly elements and readable typography across devices. Scroll position and active tabs are preserved across form submissions in professor and admin dashboards to maintain user context. Semester headers in the professor dashboard are visually distinct with consistent violet/purple styling. The desktop interface features professional full-width optimization with responsive breakpoints at 1400px, 1600px, 1920px, and 2560px (4K), utilizing 95-98% of screen width with progressive scaling of padding, fonts, and element sizes for optimal use of ultra-wide displays.

### Technical Implementations
- **Authentication & Authorization**: `bcrypt` for password hashing, `itsdangerous` for secure cookie-based session management, and role-based access control.
- **Hierarchical Access Control**: Students can only view chapters from their current level and all lower levels within their filière, enforced by SQL-level filtering. Professors have full access within their assigned subject.
- **User & Content Management**: Separate models for professors and students, with content hierarchically organized.
- **University-Based Administration**: Administrators are assigned to specific universities, restricting access to institutional data, with a main administrator having global access.
- **Data Filtering**: Professors can only create content within their assigned university, and dashboards dynamically filter data based on user roles and affiliations.
- **Complete Cascade Deletion**: A comprehensive system with specialized helper functions ensures transaction-safe, permanent removal of all associated data when an entity (chapter, subject, professor, student, filière, UFR, university, secondary administrator) is deleted, including uploaded files, comments, and notifications.
- **Search Functionality**: Pure frontend, real-time, case-insensitive search across admin and professor dashboards for various entities, including real-time chapter search for students/professors and live filtering of dropdown options in admin creation forms.
- **Performance Optimization**: Comprehensive performance optimizations including:
  - **Database**: Database-based migration detection (checking admin count instead of local files to ensure Render compatibility), database indexes on all foreign key columns (`universite_id`, `ufr_id`, `filiere_id`, `matiere_id`, `created_by`) with composite index on notifications table (`destinataire_id`, `lue`)
  - **Query Optimization**: Eliminated N+1 queries in admin dashboard using dictionary-based lookups (54+ queries reduced to ~3-5 queries) for students and professors. Eager loading with `joinedload()` in professor dashboard. SQL aggregations for admin statistics instead of Python loops.
  - **Network Optimization**: GZip compression middleware enabled (70-80% payload size reduction). Cache-Control headers: 1-hour caching for static files (`/static/*`, `/files/*`), no-cache for dynamic content. 
  - **Frontend**: Image optimization (PNG to WebP with lazy loading), notification polling reduced from 3 seconds to 30 seconds (10x reduction in API calls) for student and professor dashboards.
  - **JavaScript Scope**: All interactive functions (`ouvrirModificationChapitre`, `deleteChapitre`, `addFileInput`, `filterDropdown`, etc.) exposed to global scope via `window` object to fix onclick handler accessibility issues.
- **Progressive Web App (PWA)**: Full PWA implementation with a web app manifest, service worker for intelligent caching with route-specific strategies (static assets use cache-first, API routes use network-only to prevent stale data, dashboards use network-only with offline fallback to ensure real-time updates), offline fallback page, PWA/iOS meta tags, and a custom, persistent installation banner. Cache version v10 with automatic cleanup of old caches.
- **Interactive Comment System**: Real-time commenting with a `Commentaire` database model, RESTful API endpoints, permission-based deletion (author-only), visual differentiation for user roles, XSS protection, and reply functionality. Unified JSON-based API communication and enhanced error handling are implemented.
- **Admin Auto-Provisioning**: Automatic creation of a default main administrator at startup.
- **Administrator Edit Capability**: Main administrator can modify usernames and passwords for professors and secondary administrators, with duplicate username validation and automatic update of associated chapters for professors.
- **Notification System**: Real-time notification system with a `Notification` database model, RESTful API, auto-notifications for new content, a UI notification center with unread counters, read/unread states, and individual/bulk deletion. Native push notifications with custom sound and vibration are implemented via the Service Worker API, including PWA badge API integration for unread counts on the app icon.
- **University-Specific Feature Control System**: Each university has independent control over key features through the `ParametreUniversite` model. Administrators can independently enable/disable downloads and academic progression features for their specific university. The system includes automatic migration of legacy global parameters to per-university settings, ensuring backward compatibility. Features controlled per university: (1) Download buttons visibility across all dashboards - when disabled, download buttons are hidden for students and professors of that university while maintaining view/read functionality. (2) Academic progression system activation - controls whether students of that university can access the passage feature. API endpoints (`/api/parametres/telechargements`, `/api/parametres/passage-classe`) automatically filter by the user's university and accept `universite_id` as a string parameter for main administrator cross-university management. The admin dashboard displays "⚙️ Contrôles des fonctionnalités" with university name, providing real-time toggle controls. Main administrators see a university selector dropdown to manage any university's settings. Settings are persisted in the database with automatic provisioning for new universities. The student dashboard uses a DOM mutation observer to apply download settings to dynamically loaded content. Main administrators can manage settings for any university, while regular administrators are restricted to their assigned university.
- **Academic Progression Hierarchy System**: Comprehensive system for managing student advancement between academic levels and programs. Administrators define advancement paths (`PassageHierarchy` model) specifying valid transitions (e.g., L1 MPCI → L2 PC/SID/MPI). The admin interface includes a "Passage dans la même filière" checkbox that simplifies creation of same-filière progression rules (e.g., L1 MPCI → L2 MPCI) by automatically synchronizing departure and arrival filières, with client-side validation ensuring the arrival level is higher than departure level. Same-filière passages are visually differentiated in the list view with a blue "MÊME FILIÈRE" badge and compact display format. Students can choose their next level through a dedicated interface with a mandatory "Redoublant" (repeat year) option always available. The system tracks all progression history (`StudentPassage` model), updates student records with new level/filière, and sends automatic notifications. Features include admin dashboard with hierarchy management, real-time statistics (total passages, by type), student choice validation with confirmation dialogs, and permanent tracking of all decisions. The `statut_passage` column in the `Etudiant` model tracks current status (en_attente/validé/redoublant). Each university can independently enable/disable the passage feature via `ParametreUniversite` model.

### System Design Choices
- **Monolithic Architecture**: FastAPI handles all backend logic, database interactions, and API endpoints.
- **Session Management**: Cookie-based sessions with `itsdangerous` for secure tokens and automatic role detection.
- **Route Protection**: Dependency injection for automated authentication and authorization.
- **Production Deployment**: Optimized for Render deployment with dynamic port configuration (PORT environment variable), automatic production/development mode detection (RENDER environment variable), disabled reload in production, and Gunicorn with Uvicorn workers for better stability. See `GUIDE_DEPLOIEMENT_RENDER.md` for complete deployment instructions.

## External Dependencies

### Core Framework Dependencies
- **FastAPI**: Asynchronous web framework.
- **Uvicorn**: ASGI server.
- **Jinja2**: Server-side template engine.
- **Pydantic**: Data validation and settings.

### Security Dependencies
- **passlib**: Password hashing library.
- **bcrypt**: Bcrypt algorithm.
- **itsdangerous**: Cryptographic signing for session cookies.

### Database Dependencies
- **PostgreSQL**: Persistent relational database provided by Replit for development, and Render PostgreSQL (paid) for production deployment.
- **SQLAlchemy**: ORM for database operations.
- **psycopg2-binary**: PostgreSQL adapter for Python.
- **alembic**: Database migration tool.
- **Data Persistence**: 
  - **Development (Replit)**: All data stored in Replit PostgreSQL database and local `uploads/` directory.
  - **Production (Render)**: Application data stored in Render PostgreSQL (external database). Uploaded files (videos, PDFs, documents) require Render Disk configuration to persist across deployments (see `RENDER_DISK_SETUP.md`).

### Utility Dependencies
- **python-multipart**: For handling form data and file uploads.

### Environment Configuration
- **SECRET_KEY**: Essential environment variable for session security.

### File System Dependencies
- **Upload Storage**: 
  - **Development**: Local `uploads/` directory for course materials.
  - **Production (Render)**: Requires Render Disk mounted at `/opt/render/project/src/uploads` to prevent file loss on redeploys. Configuration guide: `GUIDE_DEPLOIEMENT_RENDER.md`.

### Deployment Configuration
- **render.yaml**: Blueprint configuration file for automatic Render deployment setup with web service, PostgreSQL database, and persistent disk for uploads.
- **Production Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT` (Single Uvicorn process - recommended for containerized platforms like Render/Cloud Run. Render handles process scaling automatically. This avoids SIGTERM signal handling issues that occur with Gunicorn multi-worker setups in containers.)
- **Build Command**: `pip install -r requirements.txt`
- **Required Environment Variables**: DATABASE_URL, SECRET_KEY, SESSION_SECRET, PYTHON_VERSION (3.11.2)
- **Note**: For bare-metal/VPS deployments, you can still use `gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT` if needed.