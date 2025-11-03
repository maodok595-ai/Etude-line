"""
Migration pour ajouter les relations many-to-many pour les professeurs
- Crée les tables professeur_ufrs et professeur_filieres
- Migre les données existantes
"""

from sqlalchemy import text
from database import engine, get_db
from models import Base, Professeur
import traceback

def migrate_professeur_multi():
    """Ajoute les tables de liaison et migre les données existantes"""
    
    print("\n" + "="*70)
    print("🔄 MIGRATION : Relations multiples UFR/Filières pour professeurs")
    print("="*70)
    
    try:
        with engine.connect() as conn:
            # Étape 1: Créer les tables de liaison
            print("\n📊 Étape 1 : Création des tables de liaison...")
            
            # Vérifier si la table professeur_ufrs existe déjà
            result = conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_name = 'professeur_ufrs'
            """))
            
            if result.fetchone() is None:
                # Créer la table professeur_ufrs
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS professeur_ufrs (
                        professeur_id INTEGER NOT NULL,
                        ufr_id VARCHAR NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (professeur_id, ufr_id),
                        FOREIGN KEY (professeur_id) REFERENCES professeurs(id) ON DELETE CASCADE,
                        FOREIGN KEY (ufr_id) REFERENCES ufrs(id) ON DELETE CASCADE
                    )
                """))
                conn.commit()
                print("✅ Table professeur_ufrs créée")
            else:
                print("ℹ️  Table professeur_ufrs existe déjà")
            
            # Vérifier si la table professeur_filieres existe déjà
            result = conn.execute(text("""
                SELECT table_name 
                FROM information_schema.tables 
                WHERE table_name = 'professeur_filieres'
            """))
            
            if result.fetchone() is None:
                # Créer la table professeur_filieres
                conn.execute(text("""
                    CREATE TABLE IF NOT EXISTS professeur_filieres (
                        professeur_id INTEGER NOT NULL,
                        filiere_id VARCHAR NOT NULL,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        PRIMARY KEY (professeur_id, filiere_id),
                        FOREIGN KEY (professeur_id) REFERENCES professeurs(id) ON DELETE CASCADE,
                        FOREIGN KEY (filiere_id) REFERENCES filieres(id) ON DELETE CASCADE
                    )
                """))
                conn.commit()
                print("✅ Table professeur_filieres créée")
            else:
                print("ℹ️  Table professeur_filieres existe déjà")
            
            # Étape 2: Migrer les données existantes
            print("\n📦 Étape 2 : Migration des données existantes...")
            
            # Récupérer tous les professeurs avec UFR et filière
            result = conn.execute(text("""
                SELECT id, ufr_id, filiere_id
                FROM professeurs
                WHERE ufr_id IS NOT NULL OR filiere_id IS NOT NULL
            """))
            
            professeurs = result.fetchall()
            migrated_count = 0
            
            for prof in professeurs:
                prof_id = prof[0]
                ufr_id = prof[1]
                filiere_id = prof[2]
                
                # Migrer UFR si existe
                if ufr_id:
                    # Vérifier si la relation n'existe pas déjà
                    check = conn.execute(text("""
                        SELECT 1 FROM professeur_ufrs
                        WHERE professeur_id = :prof_id AND ufr_id = :ufr_id
                    """), {"prof_id": prof_id, "ufr_id": ufr_id})
                    
                    if check.fetchone() is None:
                        conn.execute(text("""
                            INSERT INTO professeur_ufrs (professeur_id, ufr_id)
                            VALUES (:prof_id, :ufr_id)
                        """), {"prof_id": prof_id, "ufr_id": ufr_id})
                
                # Migrer Filière si existe
                if filiere_id:
                    # Vérifier si la relation n'existe pas déjà
                    check = conn.execute(text("""
                        SELECT 1 FROM professeur_filieres
                        WHERE professeur_id = :prof_id AND filiere_id = :filiere_id
                    """), {"prof_id": prof_id, "filiere_id": filiere_id})
                    
                    if check.fetchone() is None:
                        conn.execute(text("""
                            INSERT INTO professeur_filieres (professeur_id, filiere_id)
                            VALUES (:prof_id, :filiere_id)
                        """), {"prof_id": prof_id, "filiere_id": filiere_id})
                
                migrated_count += 1
            
            conn.commit()
            print(f"✅ {migrated_count} professeur(s) migré(s) vers le nouveau système")
            
            # Étape 3: Vérification
            print("\n🔍 Étape 3 : Vérification...")
            
            result = conn.execute(text("SELECT COUNT(*) FROM professeur_ufrs"))
            ufr_count = result.fetchone()[0]
            print(f"   📊 Relations Professeur-UFR : {ufr_count}")
            
            result = conn.execute(text("SELECT COUNT(*) FROM professeur_filieres"))
            filiere_count = result.fetchone()[0]
            print(f"   📊 Relations Professeur-Filière : {filiere_count}")
            
            print("\n" + "="*70)
            print("✅ MIGRATION TERMINÉE AVEC SUCCÈS")
            print("="*70)
            print("\nℹ️  Les anciennes colonnes (ufr_id, filiere_id, matiere_id)")
            print("   sont conservées pour la rétrocompatibilité.")
            print("   Elles peuvent être supprimées une fois que tout fonctionne.")
            print("="*70 + "\n")
            
            return True
            
    except Exception as e:
        print(f"\n❌ ERREUR lors de la migration : {e}")
        traceback.print_exc()
        return False

if __name__ == "__main__":
    migrate_professeur_multi()
