"""
Migration pour configurer la suppression en cascade des données d'un professeur
Lorsqu'un professeur est supprimé, tous ses chapitres et contenus seront également supprimés
"""

from database import engine, SessionLocal
from sqlalchemy import text

def fix_professor_cascade_deletion():
    """Configurer les contraintes FK pour supprimer en cascade les données du professeur"""
    with engine.connect() as conn:
        try:
            print("🔧 Début de la configuration des suppressions en cascade pour les professeurs...")
            
            # 1. Supprimer et recréer la contrainte FK sur chapitres_complets.created_by
            print("\n📋 Traitement de la table chapitres_complets...")
            
            # Trouver toutes les contraintes FK sur created_by dans chapitres_complets
            result = conn.execute(text("""
                SELECT tc.constraint_name
                FROM information_schema.table_constraints AS tc
                JOIN information_schema.key_column_usage AS kcu 
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_schema = kcu.table_schema
                WHERE tc.table_name = 'chapitres_complets' 
                    AND tc.constraint_type = 'FOREIGN KEY'
                    AND kcu.column_name = 'created_by'
            """))
            
            chapitre_constraints = result.fetchall()
            for constraint in chapitre_constraints:
                constraint_name = constraint[0]
                conn.execute(text(f"""
                    ALTER TABLE chapitres_complets 
                    DROP CONSTRAINT {constraint_name}
                """))
                print(f"✅ Contrainte FK sur chapitres_complets.created_by supprimée: {constraint_name}")
            
            if not chapitre_constraints:
                print("ℹ️  Aucune contrainte FK trouvée sur chapitres_complets.created_by")
            
            # Ajouter la nouvelle contrainte avec ON DELETE CASCADE
            conn.execute(text("""
                ALTER TABLE chapitres_complets 
                ADD CONSTRAINT chapitres_complets_created_by_fkey 
                FOREIGN KEY (created_by) 
                REFERENCES professeurs(username) 
                ON DELETE CASCADE
            """))
            print("✅ Nouvelle contrainte chapitres_complets.created_by ajoutée avec ON DELETE CASCADE")
            
            # 2. Supprimer et recréer la contrainte FK sur contents.created_by
            print("\n📋 Traitement de la table contents...")
            
            # Trouver toutes les contraintes FK sur created_by dans contents
            result = conn.execute(text("""
                SELECT tc.constraint_name
                FROM information_schema.table_constraints AS tc
                JOIN information_schema.key_column_usage AS kcu 
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_schema = kcu.table_schema
                WHERE tc.table_name = 'contents' 
                    AND tc.constraint_type = 'FOREIGN KEY'
                    AND kcu.column_name = 'created_by'
            """))
            
            content_constraints = result.fetchall()
            for constraint in content_constraints:
                constraint_name = constraint[0]
                conn.execute(text(f"""
                    ALTER TABLE contents 
                    DROP CONSTRAINT {constraint_name}
                """))
                print(f"✅ Contrainte FK sur contents.created_by supprimée: {constraint_name}")
            
            if not content_constraints:
                print("ℹ️  Aucune contrainte FK trouvée sur contents.created_by")
            
            # Ajouter la nouvelle contrainte avec ON DELETE CASCADE
            conn.execute(text("""
                ALTER TABLE contents 
                ADD CONSTRAINT contents_created_by_fkey 
                FOREIGN KEY (created_by) 
                REFERENCES professeurs(username) 
                ON DELETE CASCADE
            """))
            print("✅ Nouvelle contrainte contents.created_by ajoutée avec ON DELETE CASCADE")
            
            # 3. Supprimer et recréer la contrainte FK sur commentaires.chapitre_id
            print("\n📋 Traitement de la table commentaires...")
            
            # Trouver toutes les contraintes FK sur chapitre_id dans commentaires
            result = conn.execute(text("""
                SELECT tc.constraint_name
                FROM information_schema.table_constraints AS tc
                JOIN information_schema.key_column_usage AS kcu 
                    ON tc.constraint_name = kcu.constraint_name
                    AND tc.table_schema = kcu.table_schema
                WHERE tc.table_name = 'commentaires' 
                    AND tc.constraint_type = 'FOREIGN KEY'
                    AND kcu.column_name = 'chapitre_id'
            """))
            
            commentaire_constraints = result.fetchall()
            for constraint in commentaire_constraints:
                constraint_name = constraint[0]
                conn.execute(text(f"""
                    ALTER TABLE commentaires 
                    DROP CONSTRAINT {constraint_name}
                """))
                print(f"✅ Contrainte FK sur commentaires.chapitre_id supprimée: {constraint_name}")
            
            if not commentaire_constraints:
                print("ℹ️  Aucune contrainte FK trouvée sur commentaires.chapitre_id")
            
            # Ajouter la nouvelle contrainte avec ON DELETE CASCADE
            conn.execute(text("""
                ALTER TABLE commentaires 
                ADD CONSTRAINT commentaires_chapitre_id_fkey 
                FOREIGN KEY (chapitre_id) 
                REFERENCES chapitres_complets(id) 
                ON DELETE CASCADE
            """))
            print("✅ Nouvelle contrainte commentaires.chapitre_id ajoutée avec ON DELETE CASCADE")
            
            # 4. Créer un trigger/fonction pour supprimer les notifications
            print("\n📋 Configuration de la suppression des notifications...")
            
            # Supprimer la fonction si elle existe déjà
            conn.execute(text("""
                DROP FUNCTION IF EXISTS delete_professor_related_data() CASCADE
            """))
            
            # Créer la fonction qui supprime les notifications
            conn.execute(text("""
                CREATE FUNCTION delete_professor_related_data()
                RETURNS TRIGGER AS $$
                BEGIN
                    -- Supprimer les notifications pour le professeur
                    DELETE FROM notifications 
                    WHERE destinataire_type = 'prof' 
                    AND destinataire_id = OLD.id;
                    
                    RETURN OLD;
                END;
                $$ LANGUAGE plpgsql;
            """))
            print("✅ Fonction de suppression des notifications créée")
            
            # Créer le trigger BEFORE DELETE
            conn.execute(text("""
                DROP TRIGGER IF EXISTS trigger_delete_professor_data ON professeurs
            """))
            
            conn.execute(text("""
                CREATE TRIGGER trigger_delete_professor_data
                BEFORE DELETE ON professeurs
                FOR EACH ROW
                EXECUTE FUNCTION delete_professor_related_data()
            """))
            print("✅ Trigger de suppression configuré")
            
            conn.commit()
            print("\n🎉 Migration terminée avec succès!")
            print("ℹ️  Les professeurs peuvent maintenant être supprimés avec toutes leurs données associées:")
            print("   - Chapitres créés (CASCADE)")
            print("   - Contenus créés (CASCADE)")
            print("   - Commentaires sur les chapitres (CASCADE via chapitres)")
            print("   - Notifications reçues (TRIGGER)")
            
        except Exception as e:
            print(f"❌ Erreur lors de la migration: {e}")
            conn.rollback()
            raise

if __name__ == "__main__":
    fix_professor_cascade_deletion()
