#!/usr/bin/env python3
"""
Déployement robuste d'Étude LINE pour Cloud Run
Auteur: Maodo Ka
"""
import os
import sys
import traceback

def get_port():
    """Obtient le port avec plusieurs fallbacks"""
    port_candidates = [
        os.environ.get("PORT"),
        os.environ.get("REPLIT_PORT"),
        os.environ.get("SERVER_PORT"),
        "5000"
    ]
    
    for port in port_candidates:
        if port:
            try:
                return int(port)
            except (ValueError, TypeError):
                continue
    return 5000

def main():
    """Point d'entrée principal robuste"""
    try:
        # Import de l'application principale
        from main import app
        
        # Configuration du serveur
        import uvicorn
        port = get_port()
        host = "0.0.0.0"
        
        print(f"""
🚀 Étude LINE - Déploiement Production
📍 Port: {port}
🌐 Host: {host}
👨‍💻 Auteur: Maodo Ka
🏛️ Application éducative complète
        """)
        
        # Configuration robuste d'uvicorn
        config = uvicorn.Config(
            app=app,
            host=host,
            port=port,
            log_level="info",
            access_log=True,
            use_colors=True,
            workers=1,  # Un seul worker pour Cloud Run
            timeout_keep_alive=65,  # Timeout compatible Cloud Run
            timeout_graceful_shutdown=30
        )
        
        server = uvicorn.Server(config)
        server.run()
        
    except ImportError as e:
        print(f"❌ Erreur d'import de l'application: {e}")
        print("Tentative de démarrage en mode minimal...")
        traceback.print_exc()
        
        # Mode minimal en cas d'échec
        from fastapi import FastAPI
        from fastapi.responses import HTMLResponse
        
        minimal_app = FastAPI(title="Étude LINE - Mode minimal")
        
        @minimal_app.get("/", response_class=HTMLResponse)
        async def home():
            return """
            <html><body style="font-family:sans-serif;text-align:center;padding:50px;">
            <h1>🎓 Étude LINE</h1>
            <p>Application en cours de chargement...</p>
            <p>Mode minimal actif - veuillez patienter</p>
            <p><strong>Auteur:</strong> Maodo Ka</p>
            </body></html>
            """
        
        import uvicorn
        port = get_port()
        uvicorn.run(minimal_app, host="0.0.0.0", port=port)
        
    except Exception as e:
        print(f"❌ Erreur critique: {e}")
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main()