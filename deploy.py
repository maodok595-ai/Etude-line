#!/usr/bin/env python3
import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

# Application ultra-simple pour le déploiement
app = FastAPI(title="Étude LINE")

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Étude LINE - Déployée !</title>
        <meta charset="UTF-8">
        <style>
            body { 
                font-family: 'Segoe UI', sans-serif; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                margin: 0; padding: 0; min-height: 100vh;
                display: flex; align-items: center; justify-content: center;
                color: white;
            }
            .card { 
                background: rgba(255,255,255,0.15);
                backdrop-filter: blur(10px);
                border-radius: 20px;
                padding: 40px;
                text-align: center;
                box-shadow: 0 8px 32px rgba(0,0,0,0.3);
                max-width: 500px;
            }
            .title { font-size: 3em; margin-bottom: 20px; }
            .subtitle { font-size: 1.2em; margin-bottom: 30px; opacity: 0.9; }
            .btn { 
                background: #28a745; color: white; 
                padding: 15px 30px; text-decoration: none; 
                border-radius: 50px; font-weight: bold;
                display: inline-block; margin: 10px;
                transition: all 0.3s ease;
            }
            .btn:hover { transform: translateY(-2px); box-shadow: 0 5px 15px rgba(0,0,0,0.3); }
            .footer { margin-top: 30px; font-size: 0.9em; opacity: 0.7; }
        </style>
    </head>
    <body>
        <div class="card">
            <div class="title">🎓</div>
            <h1>Étude LINE</h1>
            <p class="subtitle">Application éducative déployée avec succès !</p>
            <p>Platform pour professeurs et étudiants</p>
            <br>
            <a href="/status" class="btn">📊 Statut</a>
            <a href="/about" class="btn">ℹ️ À propos</a>
            <div class="footer">
                Développé par <strong>Maodo Ka</strong><br>
                © 2025 Étude LINE - Tous droits réservés
            </div>
        </div>
    </body>
    </html>
    """

@app.get("/status")
async def status():
    return {
        "status": "✅ DEPLOYED",
        "app": "Étude LINE",
        "version": "1.0.0",
        "author": "Maodo Ka",
        "message": "Application déployée avec succès sur Replit!"
    }

@app.get("/about")
async def about():
    return {
        "name": "Étude LINE",
        "description": "Application éducative FastAPI",
        "features": [
            "Interface professeur pour publier des cours",
            "Interface étudiant pour accéder au contenu",
            "Panel administrateur avec statistiques",
            "Gestion des universités et filières",
            "Base de données PostgreSQL"
        ],
        "author": "Maodo Ka",
        "deployment": "Replit Cloud Run"
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Démarrage d'Étude LINE sur le port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)