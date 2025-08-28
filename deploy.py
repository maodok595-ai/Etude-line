#!/usr/bin/env python3
# Import the main application instead of creating a simple one
from main import app

if __name__ == "__main__":
    import uvicorn
    import os
    port = int(os.environ.get("PORT", 5000))
    print(f"🚀 Démarrage d'Étude LINE complet sur le port {port}")
    uvicorn.run(app, host="0.0.0.0", port=port)