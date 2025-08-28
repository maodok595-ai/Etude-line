#!/usr/bin/env python3
"""
Application de déploiement simplifiée pour Étude LINE
"""
import os
import sys
from pathlib import Path

# Assurer que le répertoire courant est dans le PATH
sys.path.insert(0, str(Path(__file__).parent))

def create_simple_app():
    """Crée une version simplifiée de l'app pour le déploiement"""
    from fastapi import FastAPI, Request, HTTPException
    from fastapi.responses import HTMLResponse, RedirectResponse
    from fastapi.templating import Jinja2Templates
    from fastapi.staticfiles import StaticFiles
    
    app = FastAPI(title="Étude LINE", description="Application éducative")
    
    # Montage des fichiers statiques avec gestion d'erreur
    try:
        app.mount("/static", StaticFiles(directory="static"), name="static")
    except Exception as e:
        print(f"Warning: Could not mount static files: {e}")
    
    # Templates avec gestion d'erreur  
    try:
        templates = Jinja2Templates(directory="templates")
    except Exception as e:
        print(f"Warning: Could not load templates: {e}")
        templates = None
    
    @app.get("/")
    async def home():
        """Page d'accueil simple"""
        return HTMLResponse("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Étude LINE</title>
            <meta charset="UTF-8">
            <style>
                body { font-family: Arial, sans-serif; text-align: center; padding: 50px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; }
                .container { max-width: 600px; margin: 0 auto; background: rgba(255,255,255,0.1); padding: 30px; border-radius: 15px; }
                .btn { background: #28a745; color: white; padding: 10px 20px; text-decoration: none; border-radius: 5px; margin: 10px; display: inline-block; }
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🎓 Étude LINE</h1>
                <p>Application éducative pour professeurs et étudiants</p>
                <p>Développée par <strong>Maodo Ka</strong></p>
                <br>
                <a href="/app" class="btn">🚀 Accéder à l'application</a>
                <a href="/health" class="btn">📊 Status</a>
            </div>
        </body>
        </html>
        """)
    
    @app.get("/health")
    async def health():
        """Endpoint de santé"""
        return {
            "status": "ok", 
            "app": "etude-line",
            "version": "1.0.0",
            "author": "Maodo Ka"
        }
    
    @app.get("/app")
    async def redirect_to_app():
        """Redirection vers l'application principale"""
        try:
            # Essaie d'importer l'application principale
            from main import app as main_app
            return RedirectResponse(url="/main/")
        except Exception as e:
            return HTMLResponse(f"""
            <html>
            <head><title>Étude LINE - Chargement</title></head>
            <body style="font-family: Arial; text-align: center; padding: 50px;">
                <h1>🔄 Application en cours de chargement...</h1>
                <p>L'application principale se charge. Veuillez patienter...</p>
                <p><a href="/">← Retour à l'accueil</a></p>
                <script>
                    setTimeout(() => window.location.reload(), 5000);
                </script>
            </body>
            </html>
            """)
    
    return app

# Créer l'application
app = create_simple_app()

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run(app, host="0.0.0.0", port=port)