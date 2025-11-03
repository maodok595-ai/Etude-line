#!/usr/bin/env python3
"""
Script de diagnostic pour vérifier la configuration du Render Disk
À exécuter sur Render via le Shell pour diagnostiquer les problèmes de stockage
"""
import os
from pathlib import Path

print("=" * 70)
print("🔍 DIAGNOSTIC RENDER DISK - Étude LINE")
print("=" * 70)
print()

# Vérifier le dossier uploads
uploads_dir = Path("uploads")
print(f"📁 Dossier uploads local: {uploads_dir.absolute()}")
print(f"   Existe: {'✅ OUI' if uploads_dir.exists() else '❌ NON'}")
if uploads_dir.exists():
    print(f"   Est un dossier: {'✅ OUI' if uploads_dir.is_dir() else '❌ NON'}")
    # Compter les fichiers
    try:
        files = list(uploads_dir.rglob("*"))
        file_count = sum(1 for f in files if f.is_file())
        dir_count = sum(1 for f in files if f.is_dir())
        print(f"   Fichiers: {file_count}")
        print(f"   Sous-dossiers: {dir_count}")
    except Exception as e:
        print(f"   ❌ Erreur lors de la lecture: {e}")
print()

# Vérifier le chemin Render Disk attendu
render_disk_path = Path("/opt/render/project/src/uploads")
print(f"💾 Render Disk attendu: {render_disk_path}")
print(f"   Existe: {'✅ OUI' if render_disk_path.exists() else '❌ NON - DISQUE NON MONTÉ'}")
if render_disk_path.exists():
    print(f"   Est un dossier: {'✅ OUI' if render_disk_path.is_dir() else '❌ NON'}")
    # Compter les fichiers
    try:
        files = list(render_disk_path.rglob("*"))
        file_count = sum(1 for f in files if f.is_file())
        dir_count = sum(1 for f in files if f.is_dir())
        print(f"   Fichiers: {file_count}")
        print(f"   Sous-dossiers: {dir_count}")
    except Exception as e:
        print(f"   ❌ Erreur lors de la lecture: {e}")
print()

# Vérifier si on est sur Render
is_render = os.getenv("RENDER") == "true"
print(f"🌐 Environnement Render: {'✅ OUI' if is_render else '❌ NON (local)'}")
print()

# Diagnostic final
print("=" * 70)
print("📊 DIAGNOSTIC")
print("=" * 70)

if not is_render:
    print("ℹ️  Vous êtes en environnement LOCAL (Replit)")
    print("   Les fichiers sont dans ./uploads/ (normal)")
elif render_disk_path.exists():
    print("✅ RENDER DISK CORRECTEMENT MONTÉ !")
    print(f"   Chemin: {render_disk_path}")
    print()
    print("🔧 Action requise:")
    print("   Le code doit utiliser ce chemin en production.")
    print("   Vérifiez que main.py utilise le bon chemin.")
else:
    print("❌ RENDER DISK NON CONFIGURÉ !")
    print()
    print("📋 SOLUTION : Suivez le guide RENDER_DISK_SETUP.md")
    print()
    print("Étapes rapides:")
    print("1. Allez sur https://dashboard.render.com")
    print("2. Cliquez sur votre Web Service")
    print("3. Menu 'Disks' → 'Add Disk'")
    print("4. Name: uploads-storage")
    print("5. Mount Path: /opt/render/project/src/uploads")
    print("6. Size: 1 GB (minimum)")
    print("7. Cliquez 'Add Disk'")
    print()
    print("Le service redémarrera automatiquement avec le disque monté.")

print("=" * 70)
