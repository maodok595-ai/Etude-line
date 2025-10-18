from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from models import Base
import os

# Configuration de la base de données
DATABASE_URL = os.getenv("EXTERNAL_DATABASE_URL") or os.getenv("DATABASE_URL", "postgresql://user:password@localhost/dbname")

# Création de l'engine et de la session avec configuration SSL
# Render PostgreSQL nécessite SSL en mode "require"
engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_recycle=300,
    connect_args={"sslmode": "require"}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def get_db():
    """Dependency pour obtenir une session de base de données"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def create_tables():
    """Créer toutes les tables"""
    Base.metadata.create_all(bind=engine)

def reset_database():
    """Supprimer et recréer toutes les tables"""
    Base.metadata.drop_all(bind=engine)
    Base.metadata.create_all(bind=engine)