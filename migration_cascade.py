"""
Migration pour ajouter ON DELETE CASCADE aux Foreign Keys
Date: 28 octobre 2025
Objectif: Corriger le bug de suppression en cascade des UFR/Filières/Matières
"""

from database import engine
from sqlalchemy import text

def apply_cascade_migration():
    """Applique les contraintes CASCADE sur les Foreign Keys"""
    
    print("🔄 Début de la migration CASCADE...")
    
    with engine.connect() as conn:
        # 1. Filiere.ufr_id
        conn.execute(text('ALTER TABLE filieres DROP CONSTRAINT IF EXISTS filieres_ufr_id_fkey'))
        conn.execute(text('ALTER TABLE filieres ADD CONSTRAINT filieres_ufr_id_fkey FOREIGN KEY (ufr_id) REFERENCES ufrs(id) ON DELETE CASCADE'))
        print('✅ Filiere.ufr_id: CASCADE ajouté')
        
        # 2. Matiere.filiere_id
        conn.execute(text('ALTER TABLE matieres DROP CONSTRAINT IF EXISTS matieres_filiere_id_fkey'))
        conn.execute(text('ALTER TABLE matieres ADD CONSTRAINT matieres_filiere_id_fkey FOREIGN KEY (filiere_id) REFERENCES filieres(id) ON DELETE CASCADE'))
        print('✅ Matiere.filiere_id: CASCADE ajouté')
        
        # 3. Etudiant.ufr_id et filiere_id
        conn.execute(text('ALTER TABLE etudiants DROP CONSTRAINT IF EXISTS etudiants_ufr_id_fkey'))
        conn.execute(text('ALTER TABLE etudiants ADD CONSTRAINT etudiants_ufr_id_fkey FOREIGN KEY (ufr_id) REFERENCES ufrs(id) ON DELETE CASCADE'))
        conn.execute(text('ALTER TABLE etudiants DROP CONSTRAINT IF EXISTS etudiants_filiere_id_fkey'))
        conn.execute(text('ALTER TABLE etudiants ADD CONSTRAINT etudiants_filiere_id_fkey FOREIGN KEY (filiere_id) REFERENCES filieres(id) ON DELETE CASCADE'))
        print('✅ Etudiant.ufr_id et filiere_id: CASCADE ajouté')
        
        # 4. ChapitreComplet
        conn.execute(text('ALTER TABLE chapitres_complets DROP CONSTRAINT IF EXISTS chapitres_complets_ufr_id_fkey'))
        conn.execute(text('ALTER TABLE chapitres_complets ADD CONSTRAINT chapitres_complets_ufr_id_fkey FOREIGN KEY (ufr_id) REFERENCES ufrs(id) ON DELETE CASCADE'))
        conn.execute(text('ALTER TABLE chapitres_complets DROP CONSTRAINT IF EXISTS chapitres_complets_filiere_id_fkey'))
        conn.execute(text('ALTER TABLE chapitres_complets ADD CONSTRAINT chapitres_complets_filiere_id_fkey FOREIGN KEY (filiere_id) REFERENCES filieres(id) ON DELETE CASCADE'))
        conn.execute(text('ALTER TABLE chapitres_complets DROP CONSTRAINT IF EXISTS chapitres_complets_matiere_id_fkey'))
        conn.execute(text('ALTER TABLE chapitres_complets ADD CONSTRAINT chapitres_complets_matiere_id_fkey FOREIGN KEY (matiere_id) REFERENCES matieres(id) ON DELETE CASCADE'))
        print('✅ ChapitreComplet: CASCADE ajouté')
        
        # 5. Professeur (SET NULL car nullable)
        conn.execute(text('ALTER TABLE professeurs DROP CONSTRAINT IF EXISTS professeurs_ufr_id_fkey'))
        conn.execute(text('ALTER TABLE professeurs ADD CONSTRAINT professeurs_ufr_id_fkey FOREIGN KEY (ufr_id) REFERENCES ufrs(id) ON DELETE SET NULL'))
        conn.execute(text('ALTER TABLE professeurs DROP CONSTRAINT IF EXISTS professeurs_filiere_id_fkey'))
        conn.execute(text('ALTER TABLE professeurs ADD CONSTRAINT professeurs_filiere_id_fkey FOREIGN KEY (filiere_id) REFERENCES filieres(id) ON DELETE SET NULL'))
        conn.execute(text('ALTER TABLE professeurs DROP CONSTRAINT IF EXISTS professeurs_matiere_id_fkey'))
        conn.execute(text('ALTER TABLE professeurs ADD CONSTRAINT professeurs_matiere_id_fkey FOREIGN KEY (matiere_id) REFERENCES matieres(id) ON DELETE SET NULL'))
        print('✅ Professeur: SET NULL ajouté')
        
        conn.commit()
        print('✅ Migration terminée avec succès !')

def verify_migration():
    """Vérifie que les contraintes CASCADE ont bien été appliquées"""
    
    print("\n📊 Vérification des contraintes Foreign Key...")
    
    with engine.connect() as conn:
        result = conn.execute(text("""
            SELECT
                tc.table_name,
                kcu.column_name,
                ccu.table_name AS foreign_table_name,
                rc.delete_rule
            FROM information_schema.table_constraints AS tc
            JOIN information_schema.key_column_usage AS kcu
                ON tc.constraint_name = kcu.constraint_name
            JOIN information_schema.constraint_column_usage AS ccu
                ON ccu.constraint_name = tc.constraint_name
            JOIN information_schema.referential_constraints AS rc
                ON rc.constraint_name = tc.constraint_name
            WHERE tc.constraint_type = 'FOREIGN KEY'
                AND tc.table_name IN ('filieres', 'matieres', 'etudiants', 'professeurs', 'chapitres_complets')
                AND kcu.column_name IN ('ufr_id', 'filiere_id', 'matiere_id')
            ORDER BY tc.table_name, kcu.column_name;
        """))
        
        print("=" * 100)
        for row in result:
            status = "✅" if row[3] in ("CASCADE", "SET NULL") else "❌"
            print(f"{status} {row[0]:20} | {row[1]:15} -> {row[2]:20} | ON DELETE {row[3]}")
        print("=" * 100)

if __name__ == "__main__":
    apply_cascade_migration()
    verify_migration()
