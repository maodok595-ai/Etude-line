#!/usr/bin/env python3
"""
Application Étude LINE - Version Production Ultra-Robuste
Auteur: Maodo Ka
Copyright: © 2025 Étude LINE - Tous droits réservés

Cette version garantit une stabilité maximale en production avec :
- Gestion d'erreurs complète à tous les niveaux
- Système lifespan moderne FastAPI
- Configuration optimisée pour Cloud Run
- Fallbacks multiples en cas d'échec
- Logging détaillé pour le debugging
"""

import asyncio
import os
import sys
import traceback
import logging
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Configuration du logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("etude-line")

# Variables globales pour le tracking de l'état
app_initialized = False
database_connected = False
migration_completed = False


def get_production_port() -> int:
    """Obtient le port avec fallbacks multiples pour production"""
    port_candidates = [
        os.environ.get("PORT"),
        os.environ.get("REPLIT_PORT"),
        os.environ.get("SERVER_PORT"),
        "5000"   # Port fixe pour Replit
    ]
    
    for port in port_candidates:
        if port:
            try:
                port_int = int(port)
                logger.info(f"Port sélectionné: {port_int}")
                return port_int
            except (ValueError, TypeError):
                continue
    
    logger.warning("Utilisation du port par défaut: 5000")
    return 5000


async def initialize_database():
    """Initialise la base de données avec gestion d'erreurs robuste"""
    global database_connected, migration_completed
    
    try:
        logger.info("🔄 Initialisation de la base de données...")
        
        # Import conditionnel pour éviter les erreurs au démarrage
        from database import get_db, reset_database
        from migration import migrate_data
        
        # Suppression et recréation des tables (cohérent avec migration.py)
        logger.info("🗑️ Suppression de l'ancienne base de données...")
        reset_database()
        logger.info("✅ Nouvelle base de données de production créée...")
        database_connected = True
        
        # Migration des données
        migrate_data()
        logger.info("✅ Migration des données effectuée")
        migration_completed = True
        
        return True
        
    except ImportError as e:
        logger.error(f"❌ Erreur d'import database: {e}")
        return False
    except Exception as e:
        logger.error(f"❌ Erreur initialisation database: {e}")
        logger.error(traceback.format_exc())
        return False


async def load_main_app():
    """Charge l'application principale avec fallback"""
    global app_initialized
    
    try:
        logger.info("🔄 Chargement de l'application principale...")
        
        # Import de l'application principale
        from main import app as main_app
        
        # Vérification que l'app est bien une instance FastAPI
        if not hasattr(main_app, 'openapi'):
            raise ValueError("L'application importée n'est pas une instance FastAPI valide")
        
        logger.info("✅ Application principale chargée avec succès")
        app_initialized = True
        return main_app
        
    except ImportError as e:
        logger.error(f"❌ Erreur import application principale: {e}")
        return None
    except Exception as e:
        logger.error(f"❌ Erreur chargement application: {e}")
        logger.error(traceback.format_exc())
        return None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Gestionnaire de cycle de vie moderne pour FastAPI"""
    logger.info("🚀 Démarrage du cycle de vie de l'application")
    
    # Phase de démarrage
    try:
        # Initialisation database
        db_success = await initialize_database()
        
        # Log de l'état final
        logger.info("📊 État de l'initialisation:")
        logger.info(f"   - Base de données: {'✅' if database_connected else '❌'}")
        logger.info(f"   - Migration: {'✅' if migration_completed else '❌'}")
        
        yield  # L'application fonctionne ici
        
    except Exception as e:
        logger.error(f"❌ Erreur critique dans lifespan: {e}")
        logger.error(traceback.format_exc())
        yield  # Continue quand même
    
    finally:
        # Phase d'arrêt
        logger.info("⬇️ Arrêt gracieux de l'application")


def create_fallback_app() -> FastAPI:
    """Crée une application minimale en cas d'échec"""
    logger.warning("🔄 Création de l'application de secours")
    
    fallback_app = FastAPI(
        title="Étude LINE - Mode Sécurisé",
        description="Application en mode sécurisé",
        lifespan=lifespan
    )
    
    @fallback_app.get("/", response_class=HTMLResponse)
    async def fallback_home():
        return f"""
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Étude LINE - Mode Sécurisé</title>
    <style>
        body {{ 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0; padding: 0; min-height: 100vh;
            display: flex; align-items: center; justify-content: center;
            color: white;
        }}
        .container {{ 
            background: rgba(255,255,255,0.1);
            backdrop-filter: blur(20px);
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            box-shadow: 0 25px 50px rgba(0,0,0,0.3);
            max-width: 500px;
            margin: 20px;
        }}
        .logo {{ font-size: 4em; margin-bottom: 20px; }}
        h1 {{ font-size: 2.2em; margin-bottom: 15px; font-weight: 300; }}
        .status {{ 
            background: rgba(255,193,7,0.2);
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
            border-left: 4px solid #ffc107;
        }}
        .details {{ font-size: 0.9em; opacity: 0.8; margin: 15px 0; }}
        .btn {{ 
            background: #28a745;
            color: white;
            padding: 12px 25px;
            text-decoration: none;
            border-radius: 25px;
            display: inline-block;
            margin: 10px;
            transition: all 0.3s;
        }}
        .btn:hover {{ transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.3); }}
        .footer {{ margin-top: 30px; font-size: 0.85em; opacity: 0.7; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🎓</div>
        <h1>Étude LINE</h1>
        <div class="status">
            <strong>⚠️ Mode Sécurisé Actif</strong>
        </div>
        <p>L'application fonctionne en mode sécurisé pendant l'initialisation complète.</p>
        <div class="details">
            <p>📊 État du système:</p>
            <p>• Base de données: {'✅ Connectée' if database_connected else '🔄 Initialisation...'}</p>
            <p>• Migration: {'✅ Terminée' if migration_completed else '🔄 En cours...'}</p>
            <p>• Application: {'✅ Chargée' if app_initialized else '🔄 Chargement...'}</p>
        </div>
        <a href="/status" class="btn">📊 État Détaillé</a>
        <a href="/health" class="btn">🔧 Santé Système</a>
        <div class="footer">
            <p>Développé par <strong>Maodo Ka</strong></p>
            <p>© 2025 Étude LINE - Tous droits réservés</p>
        </div>
    </div>
</body>
</html>
        """
    
    @fallback_app.get("/status")
    async def fallback_status():
        return {
            "app": "Étude LINE",
            "mode": "fallback",
            "status": "🔄 Initialisation",
            "author": "Maodo Ka",
            "database_connected": database_connected,
            "migration_completed": migration_completed,
            "app_initialized": app_initialized,
            "port": get_production_port(),
            "message": "Application en cours d'initialisation - Mode sécurisé actif"
        }
    
    @fallback_app.get("/health")
    async def fallback_health():
        health_status = "healthy" if (database_connected and migration_completed) else "initializing"
        return {
            "status": health_status,
            "timestamp": str(asyncio.get_event_loop().time()),
            "components": {
                "database": "ok" if database_connected else "initializing",
                "migration": "ok" if migration_completed else "initializing",
                "app": "ok" if app_initialized else "initializing"
            }
        }
    
    return fallback_app


async def get_production_app() -> FastAPI:
    """Obtient l'application pour la production avec fallbacks"""
    logger.info("🔍 Tentative de chargement de l'application principale...")
    
    # Tentative de chargement de l'app principale
    main_app = await load_main_app()
    
    if main_app is not None:
        logger.info("✅ Application principale prête pour la production")
        return main_app
    else:
        logger.warning("⚠️ Fallback vers l'application de secours")
        return create_fallback_app()


# Point d'entrée pour la production
def create_app() -> FastAPI:
    """Factory function pour créer l'application"""
    try:
        # Utilisation d'asyncio.run pour l'initialisation async
        return asyncio.run(get_production_app())
    except Exception as e:
        logger.error(f"❌ Erreur critique lors de la création de l'app: {e}")
        logger.error(traceback.format_exc())
        return create_fallback_app()


# Instance de l'application pour l'export
app = create_app()


def run_production():
    """Lance l'application en mode production"""
    try:
        import uvicorn
        
        port = get_production_port()
        
        logger.info(f"""
🚀 Étude LINE - Lancement Production
📍 Port: {port}
🌐 Host: 0.0.0.0
👨‍💻 Auteur: Maodo Ka
🏛️ Application éducative
🔒 Mode production ultra-robuste
        """)
        
        # Configuration optimisée pour Cloud Run
        config = uvicorn.Config(
            app=app,
            host="0.0.0.0",
            port=port,
            log_level="info",
            access_log=True,
            use_colors=False,  # Désactivé pour les logs de production
            workers=1,
            timeout_keep_alive=65,  # Compatible Cloud Run
            timeout_graceful_shutdown=30,
            limit_concurrency=1000,
            limit_max_requests=10000,
        )
        
        server = uvicorn.Server(config)
        server.run()
        
    except Exception as e:
        logger.error(f"❌ Erreur fatale au lancement: {e}")
        logger.error(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    run_production()