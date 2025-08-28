#!/bin/bash
echo "🚀 Démarrage d'Étude LINE..."
export PYTHONPATH="."
export PYTHONUNBUFFERED=1

# Test de connectivité base de données
python3 -c "from database import get_db; print('✅ DB OK')" || echo "⚠️ DB Warning"

# Démarrage avec configuration optimisée
uvicorn main:app \
  --host 0.0.0.0 \
  --port ${PORT:-5000} \
  --workers 1 \
  --timeout-keep-alive 120 \
  --access-log