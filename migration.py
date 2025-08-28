import json
import os
from datetime import datetime
from sqlalchemy.orm import Session
from database import engine, SessionLocal, create_tables
from models import *
import uuid

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

def migrate_data():
    """Migrer les données JSON vers PostgreSQL"""
    print("🔄 Début de la migration des données...")
    
    # Créer les tables
    create_tables()
    
    # Charger les données JSON
    data = load_json_data()
    
    db = SessionLocal()
    try:
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
            admin = Administrateur(
                username=admin_data["username"],
                password_hash=admin_data["password_hash"],
                nom=admin_data["nom"],
                prenom=admin_data["prenom"],
                is_main_admin=admin_data.get("is_main_admin", False)
            )
            db.merge(admin)
        
        # Migrer les professeurs
        print("👨‍🏫 Migration des professeurs...")
        for prof_data in data.get("users", {}).get("prof", []):
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
            db.merge(prof)
        
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
            db.merge(etudiant)
        
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
        
    except Exception as e:
        db.rollback()
        print(f"❌ Erreur lors de la migration: {e}")
        raise
    finally:
        db.close()

if __name__ == "__main__":
    migrate_data()