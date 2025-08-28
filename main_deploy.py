import os
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Configuration minimale pour le déploiement
app = FastAPI(title="Étude LINE")

# Mount static files
try:
    app.mount("/static", StaticFiles(directory="static"), name="static")
except Exception:
    pass

templates = Jinja2Templates(directory="templates")

@app.get("/", response_class=HTMLResponse)
async def root():
    return """
    <html>
        <head><title>Étude LINE - Déploiement</title></head>
        <body>
            <h1>🚀 Étude LINE est en cours de déploiement...</h1>
            <p>Application éducative par Maodo Ka</p>
            <p>Redirection vers l'application complète...</p>
            <script>
                setTimeout(() => {
                    window.location.href = '/main';
                }, 3000);
            </script>
        </body>
    </html>
    """

@app.get("/health")
async def health():
    return {"status": "ok", "app": "etude-line"}

# Import de l'application complète
try:
    import main
    app.mount("/main", main.app)
except Exception as e:
    print(f"Erreur import main: {e}")

if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run(app, host="0.0.0.0", port=port)