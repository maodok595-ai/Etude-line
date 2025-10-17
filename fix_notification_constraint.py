"""
Migration pour corriger les contraintes de foreign key dans la table notifications
Ajoute ON DELETE SET NULL pour permettre la suppression de chapitres
"""

from database import engine
from sqlalchemy import text

def fix_notification_constraints():
    """Corriger les contraintes de foreign key dans la table notifications"""
    with engine.connect() as conn:
        try:
            print("🔧 Début de la correction des contraintes de foreign key...")
            
            # Trouver et supprimer TOUTES les contraintes FK sur chapitre_id
            result = conn.execute(text("""
                SELECT tc.constraint_name
                FROM information_schema.table_constraints AS tc
                JOIN information_schema.key_column_usage AS kcu 
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_schema = kcu.table_schema
                WHERE tc.table_name = 'notifications' 
                    AND tc.constraint_type = 'FOREIGN KEY'
                    AND kcu.column_name = 'chapitre_id'
            """))
            
            chapitre_constraints = result.fetchall()
            for constraint in chapitre_constraints:
                constraint_name = constraint[0]
                conn.execute(text(f"""
                    ALTER TABLE notifications 
                    DROP CONSTRAINT {constraint_name}
                """))
                print(f"✅ Contrainte FK sur chapitre_id supprimée: {constraint_name}")
            
            if not chapitre_constraints:
                print("ℹ️  Aucune contrainte FK trouvée sur chapitre_id")
            
            # Ajouter la nouvelle contrainte avec ON DELETE SET NULL
            conn.execute(text("""
                ALTER TABLE notifications 
                ADD CONSTRAINT notifications_chapitre_id_fkey 
                FOREIGN KEY (chapitre_id) 
                REFERENCES chapitres_complets(id) 
                ON DELETE SET NULL
            """))
            print("✅ Nouvelle contrainte chapitre_id ajoutée avec ON DELETE SET NULL")
            
            # Trouver et supprimer TOUTES les contraintes FK sur universite_id
            result = conn.execute(text("""
                SELECT tc.constraint_name
                FROM information_schema.table_constraints AS tc
                JOIN information_schema.key_column_usage AS kcu 
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_schema = kcu.table_schema
                WHERE tc.table_name = 'notifications' 
                    AND tc.constraint_type = 'FOREIGN KEY'
                    AND kcu.column_name = 'universite_id'
            """))
            
            universite_constraints = result.fetchall()
            for constraint in universite_constraints:
                constraint_name = constraint[0]
                conn.execute(text(f"""
                    ALTER TABLE notifications 
                    DROP CONSTRAINT {constraint_name}
                """))
                print(f"✅ Contrainte FK sur universite_id supprimée: {constraint_name}")
            
            if not universite_constraints:
                print("ℹ️  Aucune contrainte FK trouvée sur universite_id")
            
            # Ajouter la nouvelle contrainte avec ON DELETE SET NULL
            conn.execute(text("""
                ALTER TABLE notifications 
                ADD CONSTRAINT notifications_universite_id_fkey 
                FOREIGN KEY (universite_id) 
                REFERENCES universites(id) 
                ON DELETE SET NULL
            """))
            print("✅ Nouvelle contrainte universite_id ajoutée avec ON DELETE SET NULL")
            
            conn.commit()
            print("🎉 Migration terminée avec succès!")
            
        except Exception as e:
            print(f"❌ Erreur lors de la migration: {e}")
            conn.rollback()
            raise

if __name__ == "__main__":
    fix_notification_constraints()
