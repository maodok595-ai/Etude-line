"""
Migration pour ajouter CASCADE sur toutes les Foreign Keys pointant vers Universite
Exécutez ce script pour mettre à jour la base de données Render avec les contraintes CASCADE
"""

import os
from sqlalchemy import create_engine, text

# Utiliser EXTERNAL_DATABASE_URL pour Render
DATABASE_URL = os.getenv("EXTERNAL_DATABASE_URL") or os.getenv("DATABASE_URL")

if not DATABASE_URL:
    print("❌ Erreur: DATABASE_URL non trouvé")
    exit(1)

print(f"🔗 Connexion à la base de données...")
engine = create_engine(DATABASE_URL)

# Liste des tables à migrer
tables_to_migrate = [
    ("ufrs", "ufrs_universite_id_fkey"),
    ("administrateurs", "administrateurs_universite_id_fkey"),
    ("professeurs", "professeurs_universite_id_fkey"),
    ("etudiants", "etudiants_universite_id_fkey"),
    ("chapitres_complets", "chapitres_complets_universite_id_fkey"),
]

print("\n" + "="*70)
print("🔄 MIGRATION CASCADE POUR SUPPRESSION D'UNIVERSITÉ")
print("="*70)
print("\n⚠️  ATTENTION: Cette migration va modifier les contraintes de clés étrangères")
print("   pour permettre la suppression en cascade des universités.\n")

with engine.connect() as conn:
    trans = None
    try:
        # Commencer une transaction
        trans = conn.begin()
        
        for i, (table_name, constraint_name) in enumerate(tables_to_migrate, 1):
            print(f"[{i}/{len(tables_to_migrate)}] Migration de la table '{table_name}'...")
            
            # DROP la contrainte existante
            drop_query = f"ALTER TABLE {table_name} DROP CONSTRAINT IF EXISTS {constraint_name}"
            conn.execute(text(drop_query))
            print(f"    ✓ Ancienne contrainte supprimée")
            
            # ADD la nouvelle contrainte avec CASCADE
            add_query = f"""
            ALTER TABLE {table_name} 
            ADD CONSTRAINT {constraint_name} 
            FOREIGN KEY (universite_id) 
            REFERENCES universites(id) 
            ON DELETE CASCADE
            """
            conn.execute(text(add_query))
            print(f"    ✅ Contrainte CASCADE ajoutée sur {table_name}.universite_id")
        
        # Valider la transaction
        trans.commit()
        
        print("\n" + "="*70)
        print("✅ MIGRATION TERMINÉE AVEC SUCCÈS")
        print("="*70)
        print("\n📝 Résumé des modifications:")
        print("   - ufrs.universite_id → ON DELETE CASCADE")
        print("   - administrateurs.universite_id → ON DELETE CASCADE")
        print("   - professeurs.universite_id → ON DELETE CASCADE")
        print("   - etudiants.universite_id → ON DELETE CASCADE")
        print("   - chapitres_complets.universite_id → ON DELETE CASCADE")
        print("\n✨ La suppression d'une université supprimera automatiquement:")
        print("   • Tous les UFRs de cette université")
        print("   • Toutes les filières (via UFR)")
        print("   • Toutes les matières (via filières)")
        print("   • Tous les chapitres de cette université")
        print("   • Tous les étudiants de cette université")
        print("   • Tous les professeurs de cette université")
        print("   • Tous les administrateurs de cette université")
        print("   • Tous les paramètres de cette université")
        print("\n")
        
    except Exception as e:
        if trans:
            trans.rollback()
        print(f"\n❌ Erreur lors de la migration: {e}")
        print("   Transaction annulée - aucune modification n'a été appliquée")
        raise
    finally:
        conn.close()

print("🔒 Connexion fermée")
