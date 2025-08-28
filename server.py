#!/usr/bin/env python3
"""
Serveur robuste pour Étude LINE - Gestion d'erreurs complète
"""
import os
import sys
import traceback
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse

# Configuration robuste
def get_port():
    """Récupère le port avec fallbacks multiples"""
    port_sources = [
        os.environ.get("PORT"),
        os.environ.get("REPLIT_PORT"), 
        os.environ.get("SERVER_PORT"),
        "5000"  # fallback final
    ]
    
    for port in port_sources:
        if port:
            try:
                return int(port)
            except (ValueError, TypeError):
                continue
    return 5000

# Création de l'application avec gestion d'erreurs
app = FastAPI(
    title="Étude LINE",
    description="Application éducative - Version déployée",
    version="1.0.0"
)

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Gestionnaire global d'erreurs"""
    error_details = {
        "error": "Erreur interne du serveur",
        "type": type(exc).__name__,
        "message": str(exc),
        "path": str(request.url),
        "method": request.method
    }
    
    print(f"ERREUR: {error_details}")
    return JSONResponse(
        status_code=500,
        content=error_details
    )

@app.get("/", response_class=HTMLResponse)
async def home():
    """Page d'accueil robuste"""
    try:
        return """
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Étude LINE - Application Éducative</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh; display: flex; align-items: center; justify-content: center;
            color: white;
        }
        .container { 
            background: rgba(255,255,255,0.1); backdrop-filter: blur(15px);
            border-radius: 25px; padding: 50px; text-align: center;
            box-shadow: 0 25px 50px rgba(0,0,0,0.3);
            max-width: 600px; width: 90%;
        }
        .logo { font-size: 4em; margin-bottom: 20px; }
        h1 { font-size: 2.5em; margin-bottom: 15px; font-weight: 300; }
        .subtitle { font-size: 1.3em; margin-bottom: 30px; opacity: 0.9; }
        .features { text-align: left; margin: 30px 0; }
        .feature { margin: 10px 0; padding: 10px 15px; background: rgba(255,255,255,0.1); border-radius: 10px; }
        .btn { 
            background: linear-gradient(45deg, #28a745, #20c997);
            color: white; padding: 15px 35px; text-decoration: none;
            border-radius: 50px; font-weight: 600; margin: 10px;
            display: inline-block; transition: all 0.3s ease;
            border: 2px solid transparent;
        }
        .btn:hover { 
            transform: translateY(-3px); 
            box-shadow: 0 10px 25px rgba(40,167,69,0.4);
            border-color: rgba(255,255,255,0.3);
        }
        .status { margin-top: 30px; padding: 15px; background: rgba(40,167,69,0.2); border-radius: 10px; }
        .footer { margin-top: 40px; font-size: 0.9em; opacity: 0.8; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">🎓</div>
        <h1>Étude LINE</h1>
        <p class="subtitle">Application éducative pour professeurs et étudiants</p>
        
        <div class="features">
            <div class="feature">👨‍🏫 Interface professeur pour publier des cours</div>
            <div class="feature">👨‍🎓 Interface étudiant pour accéder au contenu</div>
            <div class="feature">👑 Panel administrateur avec statistiques</div>
            <div class="feature">🏛️ Gestion complète des universités</div>
        </div>
        
        <div class="status">
            <strong>✅ APPLICATION DÉPLOYÉE AVEC SUCCÈS</strong>
        </div>
        
        <br>
        <a href="/health" class="btn">📊 État du serveur</a>
        <a href="/info" class="btn">ℹ️ Informations</a>
        
        <div class="footer">
            <p>Développé par <strong>Maodo Ka</strong></p>
            <p>© 2025 Étude LINE - Tous droits réservés</p>
        </div>
    </div>
</body>
</html>
        """
    except Exception as e:
        return f"<h1>Étude LINE</h1><p>Application déployée mais erreur d'affichage: {e}</p>"

@app.get("/health")
async def health():
    """Endpoint de santé détaillé"""
    try:
        import platform
        import psutil
        
        return {
            "status": "✅ HEALTHY",
            "app": "Étude LINE",
            "version": "1.0.0",
            "author": "Maodo Ka",
            "deployment": "Replit Cloud",
            "timestamp": str(os.environ.get('TIMESTAMP', 'N/A')),
            "port": get_port(),
            "python_version": platform.python_version(),
            "platform": platform.platform(),
            "memory_usage": f"{psutil.virtual_memory().percent}%" if 'psutil' in sys.modules else "N/A",
            "environment_vars": {
                "PORT": os.environ.get("PORT", "Non définie"),
                "REPLIT_PORT": os.environ.get("REPLIT_PORT", "Non définie"),
                "DATABASE_URL": "Configurée" if os.environ.get("DATABASE_URL") else "Non configurée"
            }
        }
    except Exception as e:
        return {
            "status": "⚠️ PARTIAL", 
            "error": str(e),
            "app": "Étude LINE",
            "port": get_port()
        }

@app.get("/info")
async def info():
    """Informations sur l'application"""
    return {
        "name": "Étude LINE",
        "description": "Application éducative FastAPI déployée sur Replit",
        "author": "Maodo Ka",
        "features": [
            "Authentification multi-rôles (Admin/Professeur/Étudiant)",
            "Gestion hiérarchique des universités",
            "Publication de cours, exercices et solutions",
            "Dashboard administrateur avec statistiques",
            "Interface moderne avec effets glassmorphism",
            "Base de données PostgreSQL"
        ],
        "technology_stack": [
            "FastAPI",
            "PostgreSQL", 
            "SQLAlchemy",
            "Jinja2 Templates",
            "Bootstrap CSS"
        ],
        "deployment": {
            "platform": "Replit Cloud Run",
            "status": "Production",
            "port": get_port()
        }
    }

@app.get("/test")
async def test():
    """Endpoint de test simple"""
    return {"message": "✅ Test réussi!", "app": "Étude LINE"}

# Point d'entrée principal
if __name__ == "__main__":
    try:
        import uvicorn
        port = get_port()
        
        print(f"""
🚀 Démarrage d'Étude LINE
📍 Port: {port}
🌐 Host: 0.0.0.0
👨‍💻 Auteur: Maodo Ka
        """)
        
        uvicorn.run(
            app, 
            host="0.0.0.0", 
            port=port,
            log_level="info"
        )
    except Exception as e:
        print(f"❌ Erreur de démarrage: {e}")
        traceback.print_exc()
        sys.exit(1)