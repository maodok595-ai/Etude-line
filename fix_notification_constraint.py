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
            
            # Trouver le nom de la contrainte actuelle pour chapitre_id
            result = conn.execute(text("""
                SELECT constraint_name 
                FROM information_schema.table_constraints 
                WHERE table_name = 'notifications' 
                AND constraint_type = 'FOREIGN KEY'
                AND constraint_name LIKE '%chapitre%'
            """))
            chapitre_constraint = result.fetchone()
            
            if chapitre_constraint:
                constraint_name = chapitre_constraint[0]
                print(f"📋 Contrainte trouvée: {constraint_name}")
                
                # Supprimer l'ancienne contrainte
                conn.execute(text(f"""
                    ALTER TABLE notifications 
                    DROP CONSTRAINT IF EXISTS {constraint_name}
                """))
                print("✅ Ancienne contrainte supprimée")
                
                # Ajouter la nouvelle contrainte avec ON DELETE SET NULL
                conn.execute(text("""
                    ALTER TABLE notifications 
                    ADD CONSTRAINT notifications_chapitre_id_fkey 
                    FOREIGN KEY (chapitre_id) 
                    REFERENCES chapitres_complets(id) 
                    ON DELETE SET NULL
                """))
                print("✅ Nouvelle contrainte ajoutée avec ON DELETE SET NULL")
            
            # Faire de même pour universite_id
            result = conn.execute(text("""
                SELECT constraint_name 
                FROM information_schema.table_constraints 
                WHERE table_name = 'notifications' 
                AND constraint_type = 'FOREIGN KEY'
                AND constraint_name LIKE '%universite%'
            """))
            universite_constraint = result.fetchone()
            
            if universite_constraint:
                constraint_name = universite_constraint[0]
                print(f"📋 Contrainte université trouvée: {constraint_name}")
                
                conn.execute(text(f"""
                    ALTER TABLE notifications 
                    DROP CONSTRAINT IF EXISTS {constraint_name}
                """))
                print("✅ Ancienne contrainte université supprimée")
                
                conn.execute(text("""
                    ALTER TABLE notifications 
                    ADD CONSTRAINT notifications_universite_id_fkey 
                    FOREIGN KEY (universite_id) 
                    REFERENCES universites(id) 
                    ON DELETE SET NULL
                """))
                print("✅ Nouvelle contrainte université ajoutée avec ON DELETE SET NULL")
            
            conn.commit()
            print("🎉 Migration terminée avec succès!")
            
        except Exception as e:
            print(f"❌ Erreur lors de la migration: {e}")
            conn.rollback()
            raise

if __name__ == "__main__":
    fix_notification_constraints()
