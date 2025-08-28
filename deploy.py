#!/usr/bin/env python3
"""
Script de déploiement définitif pour Étude LINE
Utilise l'application production ultra-robuste
Auteur: Maodo Ka
"""

# Import direct de l'application production
from app_production import run_production

if __name__ == "__main__":
    # Lance directement l'application production
    run_production()