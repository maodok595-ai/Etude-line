import json
import os
from datetime import datetime
from sqlalchemy.orm import Session
from database import engine, SessionLocal, create_tables, reset_database
from models import *
import uuid
from passlib.context import CryptContext

# Configuration du hachage des mots de passe
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password_safe(password: str) -> str:
    """Hash password with bcrypt 72-byte limit handling"""
    password_bytes = password.encode('utf-8')
    if len(password_bytes) <= 72:
        return pwd_context.hash(password)
    
    # Truncate safely at byte boundary
    truncated = password_bytes[:72]
    # Ensure we don't cut in the middle of a multi-byte character
    while len(truncated) > 0:
        try:
            safe_password = truncated.decode('utf-8')
            return pwd_context.hash(safe_password)
        except UnicodeDecodeError:
            truncated = truncated[:-1]
    
    # Fallback: use first 72 bytes as-is
    return pwd_context.hash(password[:72])

def create_default_data(db: Session, data: dict):
    """Créer les données de base nécessaires - éviter les doublons"""
    # Créer l'université par défaut seulement si aucune université n'existe
    existing_unis = db.query(Universite).count()
    if existing_unis == 0 and not data.get("universites"):
        print("📚 Création de l'université par défaut...")
        universite_id = str(uuid.uuid4())
        default_universite = Universite(
            id=universite_id,
            nom="Université Virtuelle",
            code="UV"
        )
        db.merge(default_universite)
        
        # Créer UFR par défaut
        ufr_id = str(uuid.uuid4())
        default_ufr = UFR(
            id=ufr_id,
            nom="UFR Sciences",
            code="SCI",
            universite_id=universite_id
        )
        db.merge(default_ufr)
        
        # Créer filière par défaut
        filiere_id = str(uuid.uuid4())
        default_filiere = Filiere(
            id=filiere_id,
            nom="Informatique",
            code="INFO",
            ufr_id=ufr_id
        )
        db.merge(default_filiere)
    
    # Créer ou mettre à jour l'administrateur principal
    existing_admin = db.query(Administrateur).filter_by(username="kamaodo65").first()
    admin_hash = hash_password_safe("admin123")
    if not existing_admin:
        print("👑 Création de l'administrateur principal...")
        admin = Administrateur(
            username="kamaodo65",
            password_hash=admin_hash,
            nom="Ka",
            prenom="Maodo",
            is_main_admin=True,
            universite_id=None  # Admin principal n'a pas d'université spécifique
        )
        db.add(admin)
    else:
        print("🔄 Mise à jour du mot de passe de l'administrateur principal...")
        existing_admin.password_hash = admin_hash
        # S'assurer que l'admin principal n'a pas d'université
        if not existing_admin.is_main_admin:
            existing_admin.is_main_admin = True
            existing_admin.universite_id = None
        
    # Créer ou mettre à jour le professeur par défaut s'il n'y a pas de données JSON
    if not data.get("users", {}).get("prof"):
        existing_prof = db.query(Professeur).filter_by(username="Abdousalam00").first()
        prof_hash = hash_password_safe("prof123")
        if not existing_prof:
            print("👨‍🏫 Création du professeur par défaut...")
            prof = Professeur(
                username="Abdousalam00",
                password_hash=prof_hash,
                nom="Diallo",
                prenom="Abdou Salam",
                specialite="Informatique"
            )
            db.add(prof)
        else:
            print("🔄 Mise à jour du mot de passe du professeur par défaut...")
            existing_prof.password_hash = prof_hash
    
    db.commit()

def load_json_data():
    """Charger les données JSON existantes"""
    if os.path.exists("data.json"):
        with open("data.json", "r", encoding="utf-8") as f:
            return json.load(f)
    return {
        "users": {"prof": [], "etudiant": [], "admin": []},
        "universites": [],
        "ufrs": [],
        "filieres": [],
        "matieres": [],
        "contents": [],
        "chapitres_complets": []
    }

def clean_uploads_directory():
    """Nettoyer le dossier uploads pour une installation propre"""
    import shutil
    from pathlib import Path
    
    uploads_dir = Path("uploads")
    if uploads_dir.exists():
        print("🧹 Nettoyage du dossier uploads...")
        shutil.rmtree(uploads_dir)
    
    # Recréer les dossiers de base
    for folder in ["cours", "exercices", "solutions"]:
        (uploads_dir / folder).mkdir(parents=True, exist_ok=True)
    print("📁 Dossiers uploads recréés proprement")

def ensure_uploads_directories():
    """Créer les dossiers uploads s'ils n'existent pas (sans suppression)"""
    from pathlib import Path
    
    uploads_dir = Path("uploads")
    
    # Créer les dossiers de base uniquement s'ils n'existent pas
    for folder in ["cours", "exercices", "solutions"]:
        folder_path = uploads_dir / folder
        if not folder_path.exists():
            folder_path.mkdir(parents=True, exist_ok=True)
            print(f"📁 Dossier {folder} créé")
    print("✅ Dossiers uploads vérifiés")

def migrate_data():
    """Migrer les données JSON vers PostgreSQL"""
    print("🔄 Début de la migration des données...")
    
    # Créer les tables si elles n'existent pas (sans suppression)
    print("🔧 Vérification de la base de données...")
    create_tables()
    print("✅ Base de données prête...")
    
    # Créer les dossiers uploads si nécessaire (sans suppression)
    ensure_uploads_directories()
    
    # Charger les données JSON
    data = load_json_data()
    
    db = SessionLocal()
    try:
        # Créer les données de base si elles n'existent pas
        create_default_data(db, data)  # RÉACTIVÉ - Données par défaut necessaires
        # Migrer les universités
        print("📚 Migration des universités...")
        for uni_data in data.get("universites", []):
            universite = Universite(
                id=uni_data["id"],
                nom=uni_data["nom"],
                code=uni_data["code"],
                logo_url=uni_data.get("logo_url")
            )
            db.merge(universite)
        
        # Migrer les UFR
        print("🏢 Migration des UFR...")
        for ufr_data in data.get("ufrs", []):
            ufr = UFR(
                id=ufr_data["id"],
                nom=ufr_data["nom"],
                code=ufr_data["code"],
                universite_id=ufr_data["universite_id"]
            )
            db.merge(ufr)
        
        # Migrer les filières
        print("📚 Migration des filières...")
        for filiere_data in data.get("filieres", []):
            filiere = Filiere(
                id=filiere_data["id"],
                nom=filiere_data["nom"],
                code=filiere_data["code"],
                ufr_id=filiere_data["ufr_id"]
            )
            db.merge(filiere)
        
        # Migrer les matières
        print("📖 Migration des matières...")
        for matiere_data in data.get("matieres", []):
            matiere = Matiere(
                id=matiere_data["id"],
                nom=matiere_data["nom"],
                code=matiere_data["code"],
                filiere_id=matiere_data["filiere_id"]
            )
            db.merge(matiere)
        
        # Migrer les administrateurs
        print("👑 Migration des administrateurs...")
        for admin_data in data.get("users", {}).get("admin", []):
            # Vérifier si l'admin existe déjà
            existing_admin = db.query(Administrateur).filter_by(username=admin_data["username"]).first()
            if not existing_admin:
                # Si c'est l'admin principal, pas d'université, sinon on récupère depuis les données JSON
                universite_id = None if admin_data.get("is_main_admin", False) else admin_data.get("universite_id")
                
                admin = Administrateur(
                    username=admin_data["username"],
                    password_hash=admin_data["password_hash"],
                    nom=admin_data["nom"],
                    prenom=admin_data["prenom"],
                    is_main_admin=admin_data.get("is_main_admin", False),
                    universite_id=universite_id
                )
                db.add(admin)
            else:
                print(f"   ⚠️ Administrateur {admin_data['username']} existe déjà, ignoré")
        
        # Migrer les professeurs
        print("👨‍🏫 Migration des professeurs...")
        for prof_data in data.get("users", {}).get("prof", []):
            # Vérifier si le professeur existe déjà
            existing_prof = db.query(Professeur).filter_by(username=prof_data["username"]).first()
            if not existing_prof:
                prof = Professeur(
                    username=prof_data["username"],
                    password_hash=prof_data["password_hash"],
                    nom=prof_data["nom"],
                    prenom=prof_data["prenom"],
                    specialite=prof_data["specialite"],
                    universite_id=prof_data.get("universite_id"),
                    ufr_id=prof_data.get("ufr_id"),
                    filiere_id=prof_data.get("filiere_id"),
                    matiere_id=prof_data.get("matiere_id"),
                    matiere=prof_data.get("matiere")
                )
                db.add(prof)
            else:
                print(f"   ⚠️ Professeur {prof_data['username']} existe déjà, ignoré")
        
        # Migrer les étudiants
        print("👨‍🎓 Migration des étudiants...")
        for etudiant_data in data.get("users", {}).get("etudiant", []):
            # Récupérer l'universite_id depuis la filière si pas directement disponible
            universite_id = etudiant_data.get("universite_id")
            ufr_id = etudiant_data.get("ufr_id")
            filiere_id = etudiant_data.get("filiere_id")
            
            # Si pas d'universite_id mais qu'on a filiere_id, trouver via UFR
            if not universite_id and filiere_id:
                filiere = db.query(Filiere).filter_by(id=filiere_id).first()
                if filiere:
                    ufr = db.query(UFR).filter_by(id=filiere.ufr_id).first()
                    if ufr:
                        universite_id = ufr.universite_id
                        ufr_id = ufr.id
            
            # Si on a toujours pas tous les IDs, utiliser des valeurs par défaut ou ignorer
            if not universite_id or not ufr_id or not filiere_id:
                print(f"⚠️  Étudiant {etudiant_data['username']} ignoré - IDs manquants")
                continue
            
            # Vérifier si l'étudiant existe déjà
            existing_etudiant = db.query(Etudiant).filter_by(username=etudiant_data["username"]).first()
            if not existing_etudiant:
                etudiant = Etudiant(
                    username=etudiant_data["username"],
                    password_hash=etudiant_data["password_hash"],
                    nom=etudiant_data["nom"],
                    prenom=etudiant_data["prenom"],
                    niveau=etudiant_data["niveau"],
                    universite_id=universite_id,
                    ufr_id=ufr_id,
                    filiere_id=filiere_id
                )
                db.add(etudiant)
            else:
                print(f"   ⚠️ Étudiant {etudiant_data['username']} existe déjà, ignoré")
        
        # Migrer les contenus
        print("📄 Migration des contenus...")
        for content_data in data.get("contents", []):
            content = Content(
                niveau=content_data["niveau"],
                semestre=content_data["semestre"],
                chapitre=content_data["chapitre"],
                type=content_data["type"],
                texte=content_data.get("texte"),
                fichier_nom=content_data.get("fichier_nom"),
                fichier_path=content_data.get("fichier_path"),
                matiere_id=content_data.get("matiere_id"),
                created_by=content_data["created_by"]
            )
            db.add(content)
        
        # Migrer les chapitres complets
        print("📚 Migration des chapitres complets...")
        for chapitre_data in data.get("chapitres_complets", []):
            chapitre = ChapitreComplet(
                universite_id=chapitre_data["universite_id"],
                ufr_id=chapitre_data["ufr_id"],
                filiere_id=chapitre_data["filiere_id"],
                matiere_id=chapitre_data["matiere_id"],
                niveau=chapitre_data["niveau"],
                semestre=chapitre_data["semestre"],
                chapitre=chapitre_data["chapitre"],
                titre=chapitre_data["titre"],
                cours_texte=chapitre_data.get("cours_texte"),
                cours_fichier_nom=chapitre_data.get("cours_fichier_nom"),
                cours_fichier_path=chapitre_data.get("cours_fichier_path"),
                exercice_texte=chapitre_data.get("exercice_texte"),
                exercice_fichier_nom=chapitre_data.get("exercice_fichier_nom"),
                exercice_fichier_path=chapitre_data.get("exercice_fichier_path"),
                solution_texte=chapitre_data.get("solution_texte"),
                solution_fichier_nom=chapitre_data.get("solution_fichier_nom"),
                solution_fichier_path=chapitre_data.get("solution_fichier_path"),
                created_by=chapitre_data["created_by"]
            )
            db.add(chapitre)
        
        db.commit()
        print("✅ Migration des données terminée avec succès!")
        
        # Statistiques
        print(f"📊 Statistiques de migration:")
        print(f"   - Universités: {db.query(Universite).count()}")
        print(f"   - UFR: {db.query(UFR).count()}")
        print(f"   - Filières: {db.query(Filiere).count()}")
        print(f"   - Matières: {db.query(Matiere).count()}")
        print(f"   - Administrateurs: {db.query(Administrateur).count()}")
        print(f"   - Professeurs: {db.query(Professeur).count()}")
        print(f"   - Étudiants: {db.query(Etudiant).count()}")
        print(f"   - Contenus: {db.query(Content).count()}")
        print(f"   - Chapitres complets: {db.query(ChapitreComplet).count()}")
        
        print("✅ Migration terminée - Les données sont maintenant persistantes dans PostgreSQL")
        
    except Exception as e:
        import traceback
        db.rollback()
        print(f"❌ Erreur lors de la migration: {e}")
        print("📋 Traceback complet:")
        traceback.print_exc()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    migrate_data()