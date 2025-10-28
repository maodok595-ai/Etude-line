"""
Migration pour ajouter le stockage des logos d'université dans PostgreSQL
Ajoute les colonnes logo_data (LargeBinary) et logo_content_type à la table universites
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

print("\n" + "="*70)
print("🔄 MIGRATION: STOCKAGE DES LOGOS DANS POSTGRESQL")
print("="*70)
print("\n⚠️  Cette migration ajoute deux colonnes à la table universites:")
print("   - logo_data (BYTEA) : Pour stocker l'image directement en base")
print("   - logo_content_type (VARCHAR) : Pour stocker le type MIME de l'image\n")

with engine.connect() as conn:
    trans = None
    try:
        # Commencer une transaction
        trans = conn.begin()
        
        print("[1/2] Ajout de la colonne logo_data...")
        conn.execute(text("""
            ALTER TABLE universites 
            ADD COLUMN IF NOT EXISTS logo_data BYTEA
        """))
        print("    ✅ Colonne logo_data ajoutée")
        
        print("[2/2] Ajout de la colonne logo_content_type...")
        conn.execute(text("""
            ALTER TABLE universites 
            ADD COLUMN IF NOT EXISTS logo_content_type VARCHAR(50)
        """))
        print("    ✅ Colonne logo_content_type ajoutée")
        
        # Valider la transaction
        trans.commit()
        
        print("\n" + "="*70)
        print("✅ MIGRATION TERMINÉE AVEC SUCCÈS")
        print("="*70)
        print("\n📝 Résumé des modifications:")
        print("   - universites.logo_data → BYTEA (pour stocker les images)")
        print("   - universites.logo_content_type → VARCHAR(50) (pour le type MIME)")
        print("\n💡 Avantages du stockage en base de données:")
        print("   ✅ Persistance garantie entre les redéploiements Render")
        print("   ✅ Pas besoin de Render Disk")
        print("   ✅ Sauvegarde automatique avec la base de données")
        print("   ✅ Rollback possible avec les checkpoints Replit")
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
