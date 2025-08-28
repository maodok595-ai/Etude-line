#!/bin/bash
echo "🚀 Démarrage d'Étude LINE..."
export PYTHONPATH="."
uvicorn main:app --host 0.0.0.0 --port ${PORT:-5000} --workers 1