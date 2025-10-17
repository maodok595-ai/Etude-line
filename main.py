import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
import fcntl
from pathlib import Path

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status, File, UploadFile
from fastapi.responses import HTMLResponse, RedirectResponse, FileResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, validator
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, text
import uvicorn

# Import database and models
from database import get_db, create_tables
from models import (
    Universite as UniversiteDB, UFR as UFRDB, Filiere as FiliereDB, Matiere as MatiereDB,
    Administrateur as AdministrateurDB, Professeur as ProfesseurDB, Etudiant as EtudiantDB, 
    Content, ChapitreComplet as ChapitreCompletDB, Commentaire as CommentaireDB
)
from migration import migrate_data

# Initialize FastAPI app
app = FastAPI(title="Étude LINE", description="Application éducative")
templates = Jinja2Templates(directory="templates")

# Mount static files
app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize database on startup
@app.on_event("startup")
async def startup_event():
    """Initialiser la base de données au démarrage"""
    try:
        create_tables()
        
        # Migration: Ajouter la colonne 'actif' si elle n'existe pas
        from database import engine
        with engine.connect() as conn:
            try:
                conn.execute(text("""
                    ALTER TABLE administrateurs 
                    ADD COLUMN IF NOT EXISTS actif BOOLEAN DEFAULT TRUE
                """))
                conn.commit()
                print("✅ Colonne 'actif' ajoutée aux administrateurs")
            except Exception as e:
                print(f"ℹ️ Colonne 'actif' déjà existante ou erreur: {e}")
            
            try:
                conn.execute(text("""
                    ALTER TABLE professeurs 
                    ADD COLUMN IF NOT EXISTS actif BOOLEAN DEFAULT TRUE
                """))
                conn.commit()
                print("✅ Colonne 'actif' ajoutée aux professeurs")
            except Exception as e:
                print(f"ℹ️ Colonne 'actif' déjà existante ou erreur: {e}")
        
        # Vérifier si la migration a déjà été effectuée
        migration_done_file = ".migration_done"
        force_migrate = os.getenv("MIGRATE_ON_START", "false").lower() == "true"
        
        if not os.path.exists(migration_done_file) or force_migrate:
            if force_migrate:
                print("🔄 MIGRATE_ON_START activé - Force la migration...")
            else:
                print("🔄 Première initialisation - Migration des données...")
            migrate_data()
            print("✅ Migration des données effectuée avec succès")
        else:
            print("✅ Base de données déjà migrée - Migration ignorée")
            print(f"   (Pour forcer la migration, définir MIGRATE_ON_START=true)")
        
        # Toujours vérifier et créer l'admin principal si nécessaire
        # (utile quand on change de base de données)
        from database import SessionLocal
        db = SessionLocal()
        try:
            create_default_admin_if_needed(db)
        finally:
            db.close()
            
    except Exception as e:
        print(f"⚠️ Erreur lors de l'initialisation: {e}")
        # Ne pas arrêter l'app, continuer avec les tables existantes

# Configuration from environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-change-this")

# Security setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
serializer = URLSafeTimedSerializer(SECRET_KEY)

# Data models
class UserProf(BaseModel):
    username: str
    password_hash: str
    nom: str
    prenom: str
    specialite: str
    matiere: str

class UserEtudiantDB(BaseModel):
    username: str
    password_hash: str
    nom: str
    prenom: str
    universite: str
    filiere: str
    niveau: str

class UserAdmin(BaseModel):
    username: str
    password_hash: str
    nom: str
    prenom: str

class ContentItem(BaseModel):
    id: str
    type: str  # cours|exercice|solution
    universite: str
    filiere: str
    niveau: str
    semestre: str
    matiere: str
    chapitre: str
    titre: str
    texte: str
    fichier_nom: Optional[str] = None  # nom du fichier uploadé
    fichier_path: Optional[str] = None  # chemin du fichier
    created_by: str  # username du prof

class CommentaireCreate(BaseModel):
    chapitre_id: int
    texte: str

# Ancien modèle ChapitreComplet Pydantic supprimé - nous utilisons ChapitreCompletDB SQLAlchemy


# Ancien modèle ChapitreComplet Pydantic supprimé - nous utilisons ChapitreCompletDB SQLAlchemy

# Utility functions
def now_utc() -> datetime:
    return datetime.utcnow()

def add_days(dt: datetime, days: int) -> datetime:
    return dt + timedelta(days=days)

def hash_password(password: str) -> str:
    # Bcrypt a une limite de 72 octets pour les mots de passe
    password_bytes = password.encode('utf-8')[:72]
    password_truncated = password_bytes.decode('utf-8', errors='ignore')
    return pwd_context.hash(password_truncated)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    # Bcrypt a une limite de 72 octets pour les mots de passe
    password_bytes = plain_password.encode('utf-8')[:72]
    password_truncated = password_bytes.decode('utf-8', errors='ignore')
    return pwd_context.verify(password_truncated, hashed_password)

# Database helper functions (PostgreSQL)
def create_default_admin_if_needed(db: Session) -> None:
    """Create default admin if none exists"""
    existing_admin = db.query(AdministrateurDB).filter_by(username="kamaodo65").first()
    if not existing_admin:
        print("👑 Création de l'administrateur principal par défaut...")
        default_admin = AdministrateurDB(
            username="kamaodo65",
            password_hash=hash_password("admin123"),
            nom="Maodo",
            prenom="Ka",
            is_main_admin=True
        )
        db.add(default_admin)
        db.commit()
        print("✅ Administrateur principal créé avec succès (kamaodo65/admin123)")
    else:
        print("✅ Administrateur principal déjà présent")

def authenticate_user(db: Session, username: str, password: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Authenticate user against PostgreSQL database"""
    # Try admin first
    admin = db.query(AdministrateurDB).filter_by(username=username).first()
    if admin and verify_password(password, admin.password_hash):
        # Vérifier si l'admin est actif
        if not admin.actif:
            return None  # Admin désactivé
        return "admin", {
            "id": admin.id,
            "username": admin.username,
            "nom": admin.nom,
            "prenom": admin.prenom,
            "is_main_admin": admin.is_main_admin,
            "universite_id": admin.universite_id
        }
    
    # Try professor
    prof = db.query(ProfesseurDB).filter_by(username=username).first()
    if prof and verify_password(password, prof.password_hash):
        # Vérifier si le professeur est actif
        if not prof.actif:
            return None  # Professeur désactivé
        return "prof", {
            "id": prof.id,
            "username": prof.username,
            "nom": prof.nom,
            "prenom": prof.prenom,
            "specialite": prof.specialite,
            "universite_id": prof.universite_id,
            "ufr_id": prof.ufr_id,
            "filiere_id": prof.filiere_id,
            "matiere_id": prof.matiere_id,
            "matiere": prof.matiere
        }
    
    # Try student
    etudiant = db.query(EtudiantDB).filter_by(username=username).first()
    if etudiant and verify_password(password, etudiant.password_hash):
        return "etudiant", {
            "id": etudiant.id,
            "username": etudiant.username,
            "nom": etudiant.nom,
            "prenom": etudiant.prenom,
            "niveau": etudiant.niveau,
            "universite_id": etudiant.universite_id,
            "ufr_id": etudiant.ufr_id,
            "filiere_id": etudiant.filiere_id
        }
    
    return None

def get_user_by_username(db: Session, username: str, role: str) -> Optional[Dict[str, Any]]:
    """Get user by username and role from PostgreSQL"""
    if role == "admin":
        admin = db.query(AdministrateurDB).filter_by(username=username).first()
        if admin:
            return {
                "id": admin.id,
                "username": admin.username,
                "nom": admin.nom,
                "prenom": admin.prenom,
                "is_main_admin": admin.is_main_admin,
                "universite_id": admin.universite_id
            }
    elif role == "prof":
        prof = db.query(ProfesseurDB).filter_by(username=username).first()
        if prof:
            return {
                "id": prof.id,
                "username": prof.username,
                "nom": prof.nom,
                "prenom": prof.prenom,
                "specialite": prof.specialite,
                "universite_id": prof.universite_id,
                "ufr_id": prof.ufr_id,
                "filiere_id": prof.filiere_id,
                "matiere_id": prof.matiere_id,
                "matiere": prof.matiere
            }
    elif role == "etudiant":
        etudiant = db.query(EtudiantDB).filter_by(username=username).first()
        if etudiant:
            return {
                "id": etudiant.id,
                "username": etudiant.username,
                "nom": etudiant.nom,
                "prenom": etudiant.prenom,
                "niveau": etudiant.niveau,
                "universite_id": etudiant.universite_id,
                "ufr_id": etudiant.ufr_id,
                "filiere_id": etudiant.filiere_id
            }
    return None

# Session management
def create_session_token(username: str, role: str) -> str:
    """Create signed session token"""
    return serializer.dumps({"username": username, "role": role})

def decode_session_token(token: str) -> Optional[Dict[str, str]]:
    """Decode session token"""
    try:
        return serializer.loads(token, max_age=86400)  # 24 hours
    except:
        return None

def get_current_user(request: Request) -> Optional[Tuple[str, str]]:
    """Get current user from session cookie"""
    session_token = request.cookies.get("session")
    if not session_token:
        return None
    
    session_data = decode_session_token(session_token)
    if not session_data:
        return None
    
    return session_data["role"], session_data["username"]

def require_auth(request: Request, db: Session = Depends(get_db)) -> Tuple[str, str, Dict[str, Any]]:
    """Dependency to require authentication with database access"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    
    role, username = user
    user_data = get_user_by_username(db, username, role)
    if not user_data:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return role, username, user_data

def require_prof(request: Request, db: Session = Depends(get_db)) -> Tuple[str, Dict[str, Any]]:
    """Dependency to require professor role"""
    role, username, user_data = require_auth(request, db)
    if role != "prof":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Professor access required"
        )
    return username, user_data

def require_etudiant(request: Request, db: Session = Depends(get_db)) -> Tuple[str, Dict[str, Any]]:
    """Dependency to require student role"""
    role, username, user_data = require_auth(request, db)
    if role != "etudiant":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Student access required"
        )
    return username, user_data

def require_admin(request: Request, db: Session = Depends(get_db)) -> Tuple[str, Dict[str, Any]]:
    """Dependency to require admin role"""
    role, username, user_data = require_auth(request, db)
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required"
        )
    return username, user_data

# Helper functions (PostgreSQL)
def get_student_profile(db: Session, username: str) -> Optional[Dict[str, str]]:
    """Get student profile from PostgreSQL"""
    etudiant = db.query(EtudiantDB).filter_by(username=username).first()
    if etudiant:
        universite = db.query(UniversiteDB).filter_by(id=etudiant.universite_id).first()
        ufr = db.query(UFRDB).filter_by(id=etudiant.ufr_id).first()
        filiere = db.query(FiliereDB).filter_by(id=etudiant.filiere_id).first()
        
        profile = {
            "username": etudiant.username,
            "nom": etudiant.nom,
            "prenom": etudiant.prenom,
            "niveau": etudiant.niveau,
            "universite_id": etudiant.universite_id,
            "ufr_id": etudiant.ufr_id,
            "filiere_id": etudiant.filiere_id
        }
        
        # Add names for backward compatibility
        if universite:
            profile["universite"] = universite.nom
        if ufr:
            profile["ufr"] = ufr.nom
        if filiere:
            profile["filiere"] = filiere.nom
            
        return profile
    return None

def get_professor_profile(db: Session, username: str) -> Optional[Dict[str, str]]:
    """Get professor profile from PostgreSQL"""
    prof = db.query(ProfesseurDB).filter_by(username=username).first()
    if prof:
        profile = {
            "username": prof.username,
            "nom": prof.nom,
            "prenom": prof.prenom,
            "specialite": prof.specialite,
            "universite_id": prof.universite_id,
            "ufr_id": prof.ufr_id,
            "filiere_id": prof.filiere_id,
            "matiere_id": prof.matiere_id,
            "matiere": prof.matiere
        }
        return profile
    return None

def has_content_access(username: str, semestre: str) -> bool:
    """All students have free access to content"""
    return True  # Free access for all students

def get_accessible_content(db: Session, username: str) -> List[Dict[str, Any]]:
    """Get content accessible to student based on PostgreSQL"""
    student = get_student_profile(db, username)
    if not student:
        return []
    
    # Get all content for student's filiere and niveau
    contents = db.query(Content).filter(
        and_(
            Content.matiere_id.in_(
                db.query(MatiereDB.id).filter_by(filiere_id=student["filiere_id"])
            ),
            Content.niveau == student["niveau"]
        )
    ).all()
    
    accessible_content = []
    for content in contents:
        accessible_content.append({
            "id": content.id,
            "type": content.type,
            "niveau": content.niveau,
            "semestre": content.semestre,
            "chapitre": content.chapitre,
            "texte": content.texte,
            "fichier_nom": content.fichier_nom,
            "fichier_path": content.fichier_path,
            "matiere_id": content.matiere_id,
            "created_by": content.created_by
        })
    
    return accessible_content

# Helper functions for academic structure (PostgreSQL)
def get_universites(db: Session) -> List[Dict[str, Any]]:
    """Get all universities from PostgreSQL"""
    universites = db.query(UniversiteDB).all()
    return [{"id": u.id, "nom": u.nom, "code": u.code, "logo_url": u.logo_url} for u in universites]

def get_ufrs_by_universite(db: Session, universite_id: str) -> List[Dict[str, Any]]:
    """Get UFRs for a specific university from PostgreSQL"""
    ufrs = db.query(UFRDB).filter_by(universite_id=universite_id).all()
    return [{"id": u.id, "nom": u.nom, "code": u.code, "universite_id": u.universite_id} for u in ufrs]

def get_filieres_by_ufr(db: Session, ufr_id: str) -> List[Dict[str, Any]]:
    """Get filières for a specific UFR from PostgreSQL"""
    filieres = db.query(FiliereDB).filter_by(ufr_id=ufr_id).all()
    return [{"id": f.id, "nom": f.nom, "code": f.code, "ufr_id": f.ufr_id} for f in filieres]

def get_matieres_by_filiere(db: Session, filiere_id: str) -> List[Dict[str, Any]]:
    """Get matières for a specific filière from PostgreSQL"""
    matieres = db.query(MatiereDB).filter_by(filiere_id=filiere_id).all()
    return [{"id": m.id, "nom": m.nom, "code": m.code, "filiere_id": m.filiere_id} for m in matieres]

# Helper functions to get names from IDs (PostgreSQL)
def get_universite_name(db: Session, universite_id: str) -> str:
    """Get university name from ID"""
    uni = db.query(UniversiteDB).filter_by(id=universite_id).first()
    return uni.nom if uni else "Université inconnue"

def get_ufr_name(db: Session, ufr_id: str) -> str:
    """Get UFR name from ID"""
    ufr = db.query(UFRDB).filter_by(id=ufr_id).first()
    return ufr.nom if ufr else "UFR inconnue"

def get_filiere_name(db: Session, filiere_id: str) -> str:
    """Get filière name from ID"""
    filiere = db.query(FiliereDB).filter_by(id=filiere_id).first()
    return filiere.nom if filiere else "Filière inconnue"

def get_matiere_name(db: Session, matiere_id: str) -> str:
    """Get matière name from ID"""
    matiere = db.query(MatiereDB).filter_by(id=matiere_id).first()
    return matiere.nom if matiere else "Matière inconnue"


# Routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request, db: Session = Depends(get_db)):
    """Home page with registration forms"""
    try:
        user = get_current_user(request)
        if user:
            role, username = user
            # Vérifier que l'utilisateur existe vraiment dans la base
            user_data = get_user_by_username(db, username, role)
            if user_data:
                if role == "prof":
                    return RedirectResponse(url="/dashboard/prof", status_code=303)
                elif role == "admin":
                    return RedirectResponse(url="/dashboard/admin", status_code=303)
                else:
                    return RedirectResponse(url="/dashboard/etudiant", status_code=303)
    except:
        # En cas d'erreur de session, on ignore et affiche la page d'accueil
        pass
    
    # Load academic data for form
    universites = get_universites(db)
    
    # Créer une réponse avec suppression forcée du cookie corrompu
    response = templates.TemplateResponse("index.html", {
        "request": request, 
        "universites": universites
    })
    
    # Forcer la suppression du cookie de session corrompu
    response.delete_cookie("session")
    response.delete_cookie("session", path="/")
    
    return response

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request, db: Session = Depends(get_db)):
    """Registration page for students"""
    universites = get_universites(db)
    return templates.TemplateResponse("inscription.html", {
        "request": request,
        "universites": universites
    })

@app.post("/register/prof")
async def register_prof(
    request: Request,
    nom: str = Form(...),
    prenom: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    specialite: str = Form(...),
    matiere: str = Form(...),
    db: Session = Depends(get_db)
):
    """Register new professor"""
    # Check if username already exists
    existing_admin = db.query(AdministrateurDB).filter_by(username=username).first()
    existing_prof = db.query(ProfesseurDB).filter_by(username=username).first()
    existing_etudiant = db.query(EtudiantDB).filter_by(username=username).first()
    
    if existing_admin or existing_prof or existing_etudiant:
        universites = get_universites(db)
        return templates.TemplateResponse(
            "index.html", 
            {"request": request, "error": "Ce nom d'utilisateur existe déjà", "universites": universites}
        )
    
    # Create new professor
    new_prof = ProfesseurDB(
        username=username,
        password_hash=hash_password(password),
        nom=nom,
        prenom=prenom,
        specialite=specialite,
        matiere=matiere
    )
    
    db.add(new_prof)
    db.commit()
    
    # Create session and redirect
    session_token = create_session_token(username, "prof")
    response = RedirectResponse(url="/dashboard/prof", status_code=303)
    response.set_cookie("session", session_token, httponly=True)
    
    return response

@app.post("/register/etudiant")
async def register_etudiant(
    request: Request,
    nom: str = Form(...),
    prenom: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    universite_id: str = Form(...),
    ufr_id: str = Form(...),
    filiere_id: str = Form(...),
    niveau: str = Form(...),
    db: Session = Depends(get_db)
):
    """Register new student"""
    # Check if username already exists
    existing_admin = db.query(AdministrateurDB).filter_by(username=username).first()
    existing_prof = db.query(ProfesseurDB).filter_by(username=username).first()
    existing_etudiant = db.query(EtudiantDB).filter_by(username=username).first()
    
    if existing_admin or existing_prof or existing_etudiant:
        universites = get_universites(db)
        return templates.TemplateResponse(
            "index.html", 
            {"request": request, "error": "Ce nom d'utilisateur existe déjà", "universites": universites}
        )
    
    # Create new student
    new_etudiant = EtudiantDB(
        username=username,
        password_hash=hash_password(password),
        nom=nom,
        prenom=prenom,
        universite_id=universite_id,
        ufr_id=ufr_id,
        filiere_id=filiere_id,
        niveau=niveau
    )
    
    db.add(new_etudiant)
    db.commit()
    
    # Create session and redirect to dashboard (automatic login)
    session_token = create_session_token(username, "etudiant")
    response = RedirectResponse(url="/dashboard/etudiant", status_code=303)
    response.set_cookie("session", session_token, httponly=True)
    
    return response

@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    """Login form"""
    user = get_current_user(request)
    if user:
        role, username = user
        if role == "prof":
            return RedirectResponse(url="/dashboard/prof", status_code=303)
        elif role == "admin":
            return RedirectResponse(url="/dashboard/admin", status_code=303)
        else:
            return RedirectResponse(url="/dashboard/etudiant", status_code=303)
    
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    user_type: str = Form(...),
    db: Session = Depends(get_db)
):
    """Process login with PostgreSQL authentication"""
    # Authenticate user
    auth_result = authenticate_user(db, username, password)
    
    if not auth_result or auth_result[0] != user_type:
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Nom d'utilisateur, mot de passe ou rôle incorrect"}
        )
    
    # Create session and redirect
    session_token = create_session_token(username, user_type)
    if user_type == "admin":
        redirect_url = "/dashboard/admin"
    elif user_type == "prof":
        redirect_url = "/dashboard/prof"
    else:
        redirect_url = "/dashboard/etudiant"
    
    response = RedirectResponse(url=redirect_url, status_code=303)
    response.set_cookie("session", session_token, httponly=True)
    
    return response

@app.get("/logout")
async def logout():
    """Logout user"""
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("session")
    response.delete_cookie("session", path="/")
    response.delete_cookie("session", domain=None)
    return response

@app.get("/clear")
async def clear_session():
    """Force clear all cookies and redirect to home"""
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie("session")
    response.delete_cookie("session", path="/")
    response.delete_cookie("session", domain=None)
    response.set_cookie("session", "", expires=0, max_age=0)
    return response

@app.get("/dashboard/prof", response_class=HTMLResponse)
async def dashboard_prof(request: Request, db: Session = Depends(get_db)):
    """Professor dashboard - classic version"""
    prof_username, user_data = require_prof(request, db)
    
    # Get professor's contents
    prof_contents = db.query(Content).filter(Content.created_by == prof_username).all()
    
    # Get academic structure data filtered by professor's university
    # Professors can only create chapters in their assigned university
    prof_universite_id = user_data.get("universite_id")
    
    # Get only professor's university
    universites = db.query(UniversiteDB).filter_by(id=prof_universite_id).all() if prof_universite_id else []
    
    # Get only UFRs from professor's university
    ufrs = db.query(UFRDB).filter_by(universite_id=prof_universite_id).all() if prof_universite_id else []
    
    # Get only filieres from these UFRs
    ufr_ids = [ufr.id for ufr in ufrs]
    filieres = db.query(FiliereDB).filter(FiliereDB.ufr_id.in_(ufr_ids)).all() if ufr_ids else []
    
    # Get only matieres from these filieres
    filiere_ids = [filiere.id for filiere in filieres]
    matieres = db.query(MatiereDB).filter(MatiereDB.filiere_id.in_(filiere_ids)).all() if filiere_ids else []

    # Get professor's complete chapters with ultra logical sorting
    prof_chapitres = db.query(ChapitreCompletDB).filter(ChapitreCompletDB.created_by == prof_username).all()
    
    # Ultra logical sorting: University → UFR → Filiere → Level → Semester → Matiere → Chapter
    def get_sort_key(chapitre):
        # Get names for sorting instead of IDs
        uni_nom = ""
        for uni in universites:
            if uni.id == chapitre.universite_id:
                uni_nom = uni.nom
                break
        
        ufr_nom = ""
        for ufr in ufrs:
            if ufr.id == chapitre.ufr_id:
                ufr_nom = ufr.nom
                break
        
        filiere_nom = ""
        for fil in filieres:
            if fil.id == chapitre.filiere_id:
                filiere_nom = fil.nom
                break
        
        matiere_nom = ""
        for mat in matieres:
            if mat.id == chapitre.matiere_id:
                matiere_nom = mat.nom
                break
        
        # Custom level order for proper academic progression
        level_order = {"L1": 1, "L2": 2, "L3": 3, "M1": 4, "M2": 5}
        level_sort = level_order.get(chapitre.niveau, 99)
        
        # Semester order
        semester_order = {"S1": 1, "S2": 2}
        semester_sort = semester_order.get(chapitre.semestre, 99)
        
        return (uni_nom, ufr_nom, filiere_nom, level_sort, semester_sort, matiere_nom, chapitre.chapitre)
    
    prof_chapitres.sort(key=get_sort_key)
    
    # Create hierarchical structure: Niveau → Matière → Semestre → Chapitres
    hierarchie = {}
    for chapitre in prof_chapitres:
        niveau = chapitre.niveau
        semestre = chapitre.semestre
        
        # Get matiere name
        matiere_nom = "Matière inconnue"
        matiere_id = chapitre.matiere_id
        for mat in matieres:
            if mat.id == chapitre.matiere_id:
                matiere_nom = mat.nom
                break
        
        # Initialize hierarchical structure
        if niveau not in hierarchie:
            hierarchie[niveau] = {}
        
        if matiere_nom not in hierarchie[niveau]:
            hierarchie[niveau][matiere_nom] = {
                "matiere_id": matiere_id,
                "semestres": {}
            }
        
        if semestre not in hierarchie[niveau][matiere_nom]["semestres"]:
            hierarchie[niveau][matiere_nom]["semestres"][semestre] = []
        
        hierarchie[niveau][matiere_nom]["semestres"][semestre].append(chapitre)
    
    prof = db.query(ProfesseurDB).filter(ProfesseurDB.username == prof_username).first()
    
    # Récupérer l'université du professeur pour l'affichage du logo
    prof_universite = None
    if prof_universite_id:
        universite_obj = db.query(UniversiteDB).filter(UniversiteDB.id == prof_universite_id).first()
        if universite_obj:
            prof_universite = {
                "id": universite_obj.id,
                "nom": universite_obj.nom,
                "code": universite_obj.code,
                "logo_url": universite_obj.logo_url
            }
    
    return templates.TemplateResponse("dashboard_prof.html", {
        "request": request,
        "prof": prof,
        "contents": prof_contents,
        "chapitres": prof_chapitres,
        "hierarchie": hierarchie,
        "universites": universites,
        "ufrs": ufrs,
        "filieres": filieres,
        "matieres": matieres,
        "prof_universite": prof_universite
    })

@app.post("/prof/content")
async def create_content(
    request: Request,
    type: str = Form(...),
    universite_id: str = Form(...),
    ufr_id: str = Form(...),
    filiere_id: str = Form(...),
    matiere_id: str = Form(...),
    niveau: str = Form(...),
    semestre: str = Form(...),
    chapitre: str = Form(...),
    titre: str = Form(...),
    texte: str = Form(""),
    fichier: Optional[UploadFile] = File(None),
    prof_data: Tuple[str, Dict[str, Any]] = Depends(require_prof),
    db: Session = Depends(get_db)
):
    """Create new content"""
    prof_username, prof_user_data = prof_data
    
    # Validate semester (only S1 and S2 allowed)
    if semestre not in ["S1", "S2"]:
        return RedirectResponse(url="/dashboard/prof?error=Semestre non valide (seuls S1 et S2 sont autorisés)", status_code=303)
    
    # Validate academic level
    if niveau not in ["L1", "L2", "L3", "M1", "M2"]:
        return RedirectResponse(url="/dashboard/prof?error=Niveau d'étude non valide", status_code=303)
    
    # Check if at least one content (text or file) is provided
    if not texte.strip() and not fichier:
        return RedirectResponse(url="/dashboard/prof?error=Veuillez fournir soit du contenu textuel, soit un fichier", status_code=303)
    
    # Handle file upload if provided
    fichier_nom = None
    fichier_path = None
    
    if fichier and fichier.filename:
        # Create upload directory for this content type
        upload_dir = Path("uploads") / type
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate unique filename
        file_extension = Path(fichier.filename).suffix
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        fichier_path = upload_dir / unique_filename
        
        # Save the file
        try:
            content = await fichier.read()
            with open(fichier_path, "wb") as f:
                f.write(content)
            
            fichier_nom = fichier.filename
            fichier_path = str(fichier_path)
        except Exception as e:
            return RedirectResponse(url=f"/dashboard/prof?error=Erreur lors de l'upload du fichier: {str(e)}", status_code=303)
    
    try:
        # Create new content item in PostgreSQL
        new_content = Content(
            niveau=niveau,
            semestre=semestre,
            chapitre=chapitre,
            type=type,
            texte=texte,
            fichier_nom=fichier_nom,
            fichier_path=fichier_path,
            matiere_id=matiere_id,
            created_by=prof_username
        )
        
        db.add(new_content)
        db.commit()
        db.refresh(new_content)
        
        return RedirectResponse(url="/dashboard/prof?success=Contenu publié avec succès", status_code=303)
        
    except Exception as e:
        db.rollback()
        return RedirectResponse(url=f"/dashboard/prof?error=Erreur lors de la création du contenu: {str(e)}", status_code=303)

@app.post("/prof/chapitre-complet")
async def create_chapitre_complet(
    request: Request,
    prof_data: Tuple[str, Dict[str, Any]] = Depends(require_prof),
    universite_id: str = Form(...),
    ufr_id: str = Form(...),
    filiere_id: str = Form(...),
    matiere_id: str = Form(...),
    niveau: str = Form(...),
    semestre: str = Form(...),
    chapitre: str = Form(...),
    titre: str = Form(...),
    # Cours
    cours_texte: str = Form(""),
    # Exercices
    exercice_texte: str = Form(""),
    # Solutions
    solution_texte: str = Form(""),
    db: Session = Depends(get_db)
):
    """Create a complete chapter with cours, exercice and solution"""
    prof_username, prof_user_data = prof_data
    
    # SECURITY: Verify professor can only create chapters in their assigned university
    prof_universite_id = prof_user_data.get("universite_id")
    if prof_universite_id and universite_id != prof_universite_id:
        return RedirectResponse(
            url="/dashboard/prof?error=Vous ne pouvez créer des chapitres que dans votre université", 
            status_code=303
        )
    
    # Validate semester (only S1 and S2 allowed)
    if semestre not in ["S1", "S2"]:
        return RedirectResponse(url="/dashboard/prof?error=Semestre non valide (seuls S1 et S2 sont autorisés)", status_code=303)
    
    # Validate academic level
    if niveau not in ["L1", "L2", "L3", "M1", "M2"]:
        return RedirectResponse(url="/dashboard/prof?error=Niveau d'étude non valide", status_code=303)
    
    # Récupérer tous les fichiers uploadés via le formulaire
    form_data = await request.form()
    
    # Collecter les fichiers pour chaque section
    cours_files = []
    exercice_files = []
    solution_files = []
    
    for key, value in form_data.items():
        if key.startswith('cours_fichier') and hasattr(value, 'filename') and value.filename:
            cours_files.append(value)
        elif key.startswith('exercice_fichier') and hasattr(value, 'filename') and value.filename:
            exercice_files.append(value)
        elif key.startswith('solution_fichier') and hasattr(value, 'filename') and value.filename:
            solution_files.append(value)
    
    # Validate that each section has at least text or file
    errors = []
    if not cours_texte.strip() and len(cours_files) == 0:
        errors.append("Cours: vous devez fournir soit du texte soit un fichier")
    
    if not exercice_texte.strip() and len(exercice_files) == 0:
        errors.append("Exercices: vous devez fournir soit du texte soit un fichier")
        
    if not solution_texte.strip() and len(solution_files) == 0:
        errors.append("Solutions: vous devez fournir soit du texte soit un fichier")
    
    if errors:
        error_msg = " | ".join(errors)
        return RedirectResponse(url=f"/dashboard/prof?error={error_msg}", status_code=303)
    
    # Check if chapter already exists for this context in PostgreSQL
    existing = db.query(ChapitreCompletDB).filter_by(
        filiere_id=filiere_id,
        matiere_id=matiere_id,
        niveau=niveau,
        semestre=semestre,
        chapitre=chapitre
    ).first()
    
    if existing:
        return RedirectResponse(url="/dashboard/prof?error=Ce chapitre existe déjà pour ce niveau/semestre/matière", status_code=303)

    # Helper function to save multiple files
    async def save_files(files: list, type_folder: str) -> tuple[str, str]:
        """Save multiple files and return names and paths separated by |||"""
        if not files or len(files) == 0:
            return None, None
        
        upload_dir = Path("uploads") / type_folder
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        file_names = []
        file_paths = []
        
        for file in files:
            if not file or not file.filename:
                continue
                
            file_extension = Path(file.filename).suffix
            unique_filename = f"{uuid.uuid4()}{file_extension}"
            file_path = upload_dir / unique_filename
            
            try:
                content = await file.read()
                with open(file_path, "wb") as f:
                    f.write(content)
                file_names.append(file.filename)
                file_paths.append(str(file_path))
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Erreur upload {type_folder}: {str(e)}")
        
        if len(file_names) == 0:
            return None, None
            
        # Join with ||| separator
        return "|||".join(file_names), "|||".join(file_paths)
    
    try:
        # Save files
        cours_nom, cours_path = await save_files(cours_files, "cours")
        exercice_nom, exercice_path = await save_files(exercice_files, "exercices")
        solution_nom, solution_path = await save_files(solution_files, "solutions")
        
        # Create complete chapter in PostgreSQL
        nouveau_chapitre = ChapitreCompletDB(
            universite_id=universite_id,
            ufr_id=ufr_id,
            filiere_id=filiere_id,
            matiere_id=matiere_id,
            niveau=niveau,
            semestre=semestre,
            chapitre=chapitre,
            titre=titre,
            # Cours
            cours_texte=cours_texte,
            cours_fichier_nom=cours_nom,
            cours_fichier_path=cours_path,
            # Exercices
            exercice_texte=exercice_texte,
            exercice_fichier_nom=exercice_nom,
            exercice_fichier_path=exercice_path,
            # Solutions
            solution_texte=solution_texte,
            solution_fichier_nom=solution_nom,
            solution_fichier_path=solution_path,
            created_by=prof_username
        )
        
        db.add(nouveau_chapitre)
        db.commit()
        db.refresh(nouveau_chapitre)
        
        return RedirectResponse(url="/dashboard/prof?success=Chapitre complet créé avec succès", status_code=303)
        
    except Exception as e:
        db.rollback()
        return RedirectResponse(url=f"/dashboard/prof?error=Erreur lors de la création du chapitre: {str(e)}", status_code=303)

@app.get("/uploads/{file_path:path}")
async def serve_uploaded_file(file_path: str, request: Request):
    """Serve uploaded files with proper content type for browser viewing"""
    import mimetypes
    
    # Remove uploads/ prefix if it exists to avoid double prefix
    if file_path.startswith("uploads/"):
        file_path = file_path[8:]  # Remove "uploads/" prefix
    
    file_location = Path("uploads") / file_path
    
    if not file_location.exists():
        raise HTTPException(status_code=404, detail="Fichier non trouvé")
    
    # Detect MIME type for proper browser handling
    mime_type, _ = mimetypes.guess_type(str(file_location))
    if mime_type is None:
        mime_type = 'application/octet-stream'
    
    # Détecter si c'est un appareil mobile
    user_agent = request.headers.get("user-agent", "").lower()
    is_mobile = any(mobile in user_agent for mobile in ["mobile", "android", "iphone", "ipad"])
    
    # Pour les PDF, optimiser selon le type d'appareil
    if mime_type == 'application/pdf':
        headers = {}
        
        if is_mobile:
            # Sur mobile, forcer le téléchargement car l'affichage inline pose souvent problème
            headers = {
                "Content-Disposition": f'attachment; filename="{file_location.name}"',
                "Cache-Control": "no-cache",
                "Content-Transfer-Encoding": "binary"
            }
        else:
            # Sur desktop, affichage inline
            headers = {
                "Content-Disposition": "inline",
                "Cache-Control": "public, max-age=3600"
            }
        
        return FileResponse(
            path=file_location,
            media_type=mime_type,
            headers=headers
        )
    else:
        # Pour les autres fichiers, téléchargement direct
        return FileResponse(
            path=file_location,
            filename=file_location.name,
            media_type=mime_type
        )

@app.get("/files/view/{file_path:path}")
async def view_file(file_path: str):
    """Afficher le fichier dans le navigateur (inline)"""
    import mimetypes
    
    if file_path.startswith("uploads/"):
        file_path = file_path[8:]
    
    file_location = Path("uploads") / file_path
    
    if not file_location.exists():
        raise HTTPException(status_code=404, detail="Fichier non trouvé")
    
    mime_type, _ = mimetypes.guess_type(str(file_location))
    if mime_type is None:
        mime_type = 'application/octet-stream'
    
    headers = {
        "Content-Disposition": "inline",
        "Cache-Control": "public, max-age=3600"
    }
    
    return FileResponse(
        path=file_location,
        media_type=mime_type,
        headers=headers
    )

@app.get("/files/download/{file_path:path}")
async def download_file(file_path: str):
    """Forcer le téléchargement du fichier (attachment)"""
    import mimetypes
    
    if file_path.startswith("uploads/"):
        file_path = file_path[8:]
    
    file_location = Path("uploads") / file_path
    
    if not file_location.exists():
        raise HTTPException(status_code=404, detail="Fichier non trouvé")
    
    mime_type, _ = mimetypes.guess_type(str(file_location))
    if mime_type is None:
        mime_type = 'application/octet-stream'
    
    headers = {
        "Content-Disposition": f'attachment; filename="{file_location.name}"',
        "Cache-Control": "private, no-store, must-revalidate"
    }
    
    return FileResponse(
        path=file_location,
        media_type=mime_type,
        headers=headers,
        filename=file_location.name
    )

@app.get("/dashboard/etudiant", response_class=HTMLResponse)
async def dashboard_etudiant(request: Request, db: Session = Depends(get_db)):
    """Student dashboard"""
    etudiant_username, user_data = require_etudiant(request, db)
    student = get_student_profile(db, etudiant_username)
    
    if not student:
        raise HTTPException(status_code=404, detail="Student profile not found")
    
    # Get all available semesters (S1-S2 only per level)
    all_semesters = ["S1", "S2"]
    
    # All semesters are freely accessible
    semester_status = {}
    for sem in all_semesters:
        semester_status[sem] = {
            "active": True,
            "expires_at": None
        }
    
    # Get ALL complete chapters from student's filiere (all levels: L1, L2, L3, M1, M2)
    chapitres_filiere = []
    if student and student.get("filiere_id"):
        # Get chapters from PostgreSQL using the ChapitreComplet model
        chapitres_complets = db.query(ChapitreCompletDB).filter_by(filiere_id=student["filiere_id"]).all()
        
        # Convert to dict format for template
        chapitres_filiere = []
        for chapitre in chapitres_complets:
            chapitres_filiere.append({
                "id": chapitre.id,
                "niveau": chapitre.niveau,
                "semestre": chapitre.semestre,
                "chapitre": chapitre.chapitre,
                "titre": chapitre.titre,
                "matiere_id": chapitre.matiere_id,
                "filiere_id": chapitre.filiere_id,
                "created_by": chapitre.created_by,
                # Cours
                "cours_texte": chapitre.cours_texte,
                "cours_fichier_nom": chapitre.cours_fichier_nom,
                "cours_fichier_path": chapitre.cours_fichier_path,
                # Exercices
                "exercice_texte": chapitre.exercice_texte,
                "exercice_fichier_nom": chapitre.exercice_fichier_nom,
                "exercice_fichier_path": chapitre.exercice_fichier_path,
                # Solutions
                "solution_texte": chapitre.solution_texte,
                "solution_fichier_nom": chapitre.solution_fichier_nom,
                "solution_fichier_path": chapitre.solution_fichier_path
            })
        
        # Ultra logical sorting for students: Level → Semester → Matiere → Chapter
        def get_student_sort_key(chapitre):
            # Get matiere name for sorting
            matiere_obj = db.query(MatiereDB).filter_by(id=chapitre["matiere_id"]).first()
            matiere_nom = matiere_obj.nom if matiere_obj else ""
            
            # Custom level order for proper academic progression
            level_order = {"L1": 1, "L2": 2, "L3": 3, "M1": 4, "M2": 5}
            level_sort = level_order.get(chapitre["niveau"], 99)
            
            # Semester order
            semester_order = {"S1": 1, "S2": 2}
            semester_sort = semester_order.get(chapitre["semestre"], 99)
            
            return (level_sort, semester_sort, matiere_nom, chapitre["chapitre"])
        
        chapitres_filiere.sort(key=get_student_sort_key)
    
    # Get unique subjects and chapters for filtering (from student's filiere only)
    subjects = list(set([c.get("matiere_id", "") for c in chapitres_filiere]))
    chapters = list(set([c["chapitre"] for c in chapitres_filiere]))
    
    # Get academic structure data for display
    universites = get_universites(db)
    ufrs = get_ufrs_by_universite(db, student.get("universite_id", "")) if student else []
    filieres = get_filieres_by_ufr(db, student.get("ufr_id", "")) if student else []
    matieres = get_matieres_by_filiere(db, student.get("filiere_id", "")) if student else []
    
    # Récupérer l'université de l'étudiant pour l'affichage du logo
    student_universite = None
    if student and student.get("universite_id"):
        universite_obj = db.query(UniversiteDB).filter(UniversiteDB.id == student["universite_id"]).first()
        if universite_obj:
            student_universite = {
                "id": universite_obj.id,
                "nom": universite_obj.nom,
                "code": universite_obj.code,
                "logo_url": universite_obj.logo_url
            }
    
    return templates.TemplateResponse("dashboard_etudiant.html", {
        "request": request,
        "student": student,
        "semester_status": semester_status,
        "chapitres": chapitres_filiere,
        "subjects": subjects,
        "chapters": chapters,
        "universites": universites,
        "ufrs": ufrs,
        "filieres": filieres,
        "matieres": matieres,
        "student_universite": student_universite
    })


# Admin utility endpoints
@app.get("/admin/migrate")
async def force_migration(admin_username: str = Depends(require_admin)):
    """Force data migration (admin only)"""
    migrated = migrate_data_to_new_format()
    if migrated:
        return {"message": "Migration effectuée avec succès", "migrated": True}
    else:
        return {"message": "Aucune migration nécessaire", "migrated": False}

@app.get("/admin/stats")
async def get_admin_stats(request: Request, db: Session = Depends(get_db), is_main_admin: bool = None, admin_universite_id: str = None):
    """Get system statistics (admin only)"""
    # Verify admin authentication
    role, username, user_data = require_auth(request, db)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Si les paramètres ne sont pas fournis, les récupérer depuis user_data
    if is_main_admin is None:
        is_main_admin = user_data.get("is_main_admin", False)
    if admin_universite_id is None:
        admin_universite_id = user_data.get("universite_id")
    
    # Count users (filtré par université pour admin secondaire)
    if is_main_admin:
        prof_count = db.query(ProfesseurDB).count()
        student_count = db.query(EtudiantDB).count()
        admin_count = db.query(AdministrateurDB).count()
    else:
        prof_count = db.query(ProfesseurDB).filter(ProfesseurDB.universite_id == admin_universite_id).count()
        student_count = db.query(EtudiantDB).filter(EtudiantDB.universite_id == admin_universite_id).count()
        # Admin secondaire voit son université + admin principal
        admin_count = db.query(AdministrateurDB).filter(
            (AdministrateurDB.universite_id == admin_universite_id) | (AdministrateurDB.is_main_admin == True)
        ).count()
    
    # Count content by type (from Content table) - filtré pour admin secondaire
    content_stats = {}
    if is_main_admin:
        contents = db.query(Content).all()
    else:
        # Filtrer les contenus par université via matière → filière → UFR → université
        contents = db.query(Content).join(MatiereDB).join(FiliereDB).join(UFRDB).filter(
            UFRDB.universite_id == admin_universite_id
        ).all()
    
    for content in contents:
        content_type = content.type
        content_stats[content_type] = content_stats.get(content_type, 0) + 1
    
    # Count chapitres complets by type (cours, exercice, solution) - filtré pour admin secondaire
    if is_main_admin:
        chapitres = db.query(ChapitreCompletDB).all()
    else:
        # Filtrer les chapitres par université
        chapitres = db.query(ChapitreCompletDB).join(MatiereDB).join(FiliereDB).join(UFRDB).filter(
            UFRDB.universite_id == admin_universite_id
        ).all()
    
    chapitre_stats = {
        "cours": 0,
        "exercice": 0, 
        "solution": 0
    }
    
    for chapitre in chapitres:
        # Compter les cours
        if chapitre.cours_texte or chapitre.cours_fichier_nom:
            chapitre_stats["cours"] += 1
        # Compter les exercices  
        if chapitre.exercice_texte or chapitre.exercice_fichier_nom:
            chapitre_stats["exercice"] += 1
        # Compter les solutions
        if chapitre.solution_texte or chapitre.solution_fichier_nom:
            chapitre_stats["solution"] += 1
    
    # Academic structure counts (filtré pour admin secondaire)
    if is_main_admin:
        uni_count = db.query(UniversiteDB).count()
        ufr_count = db.query(UFRDB).count()
        filiere_count = db.query(FiliereDB).count()
        matiere_count = db.query(MatiereDB).count()
    else:
        uni_count = 1  # Admin secondaire ne voit que son université
        ufr_count = db.query(UFRDB).filter(UFRDB.universite_id == admin_universite_id).count()
        # Filières des UFRs de son université
        filiere_count = db.query(FiliereDB).join(UFRDB).filter(UFRDB.universite_id == admin_universite_id).count()
        # Matières des filières de son université
        matiere_count = db.query(MatiereDB).join(FiliereDB).join(UFRDB).filter(UFRDB.universite_id == admin_universite_id).count()
    
    # Total content includes both individual contents and chapter components
    total_content = len(contents) + sum(chapitre_stats.values())
    
    return {
        "users": {
            "professeurs": prof_count,
            "etudiants": student_count,
            "administrateurs": admin_count
        },
        "contenu": content_stats,
        "chapitres": chapitre_stats,
        "subscriptions_actives": 0,  # No subscription system
        "structure_academique": {
            "universites": uni_count,
            "ufrs": ufr_count,
            "filieres": filiere_count,
            "matieres": matiere_count
        },
        "total_content": total_content,
        "total_chapitres": len(chapitres)
    }


@app.get("/content")
async def get_content(request: Request, etudiant_username: str = Depends(require_etudiant)):
    """Get accessible content for student (API endpoint)"""
    content = get_accessible_content(etudiant_username)
    return {"content": content}

@app.get("/dashboard/admin", response_class=HTMLResponse)
async def dashboard_admin(request: Request, admin_data: tuple = Depends(require_admin), db: Session = Depends(get_db)):
    """Admin dashboard"""
    admin_username, admin_user = admin_data
    
    # Déterminer si c'est l'admin principal
    is_main_admin = admin_user.get("is_main_admin", False)
    admin_universite_id = admin_user.get("universite_id")
    
    # Get all administrators (only main admin can see all admins)
    if is_main_admin:
        admins = db.query(AdministrateurDB).all()
    else:
        # Admin secondaire voit seulement les admins de son université
        admins = db.query(AdministrateurDB).filter(
            (AdministrateurDB.universite_id == admin_universite_id) | (AdministrateurDB.is_main_admin == True)
        ).all()
    
    admins_data = [{
        "id": admin.id,
        "username": admin.username,
        "nom": admin.nom,
        "prenom": admin.prenom,
        "is_main_admin": admin.is_main_admin,
        "actif": admin.actif,
        "universite_id": admin.universite_id
    } for admin in admins]
    
    # Get professors (filtered by university for secondary admins)
    if is_main_admin:
        profs = db.query(ProfesseurDB).all()
    else:
        profs = db.query(ProfesseurDB).filter(ProfesseurDB.universite_id == admin_universite_id).all()
    
    profs_data = [{
        "id": prof.id,
        "username": prof.username,
        "nom": prof.nom,
        "prenom": prof.prenom,
        "specialite": prof.specialite,
        "matiere": prof.matiere,
        "actif": prof.actif,
        "universite_id": prof.universite_id,
        "ufr_id": prof.ufr_id,
        "filiere_id": prof.filiere_id,
        "matiere_id": prof.matiere_id
    } for prof in profs]
    
    # Get students (filtered by university for secondary admins)
    if is_main_admin:
        etudiants = db.query(EtudiantDB).all()
    else:
        etudiants = db.query(EtudiantDB).filter(EtudiantDB.universite_id == admin_universite_id).all()
    
    etudiants_data = [{
        "id": etud.id,
        "username": etud.username,
        "nom": etud.nom,
        "prenom": etud.prenom,
        "niveau": etud.niveau,
        "filiere_id": etud.filiere_id,
        "universite_id": etud.universite_id
    } for etud in etudiants]
    
    # Get academic structure data (filtered for secondary admins)
    if is_main_admin:
        universites = get_universites(db)
        ufrs_data = db.query(UFRDB).all()
        filieres_data = db.query(FiliereDB).all()
        matieres_data = db.query(MatiereDB).all()
    else:
        # Admin secondaire voit seulement son université
        universites = db.query(UniversiteDB).filter(UniversiteDB.id == admin_universite_id).all()
        ufrs_data = db.query(UFRDB).filter(UFRDB.universite_id == admin_universite_id).all()
        # Filières des UFRs de son université
        ufr_ids = [ufr.id for ufr in ufrs_data]
        filieres_data = db.query(FiliereDB).filter(FiliereDB.ufr_id.in_(ufr_ids)).all() if ufr_ids else []
        # Matières des filières de son université
        filiere_ids = [fil.id for fil in filieres_data]
        matieres_data = db.query(MatiereDB).filter(MatiereDB.filiere_id.in_(filiere_ids)).all() if filiere_ids else []
    
    # Get statistics for display (filtrées par université pour admin secondaire)
    stats_response = await get_admin_stats(request, db, is_main_admin, admin_universite_id)
    
    # Récupérer l'université de l'admin secondaire pour l'affichage du logo
    admin_universite = None
    if not is_main_admin and admin_universite_id:
        universite_obj = db.query(UniversiteDB).filter(UniversiteDB.id == admin_universite_id).first()
        if universite_obj:
            admin_universite = {
                "id": universite_obj.id,
                "nom": universite_obj.nom,
                "code": universite_obj.code,
                "logo_url": universite_obj.logo_url
            }
    
    return templates.TemplateResponse("dashboard_admin.html", {
        "request": request,
        "admin": admin_user,
        "admins": admins_data,
        "profs": profs_data,
        "etudiants": etudiants_data,
        "universites": universites,
        "ufrs": ufrs_data,
        "filieres": filieres_data,
        "matieres": matieres_data,
        "stats": stats_response,
        "admin_universite": admin_universite
    })

@app.post("/admin/create-admin")
async def admin_create_admin(
    request: Request,
    nom: str = Form(...),
    prenom: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    universite_id: str = Form(...),
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    db: Session = Depends(get_db)
):
    """Create a new administrator (only for principal admin)"""
    
    # Récupérer les informations de l'admin connecté
    admin_username, admin_data = admin_info
    
    # Vérifier que seul l'admin principal peut créer des admins
    if not admin_data.get("is_main_admin", False):
        return RedirectResponse("/dashboard/admin?error=Seul l'administrateur principal peut créer des administrateurs", status_code=303)
    
    try:
        # Vérifier si le nom d'utilisateur existe déjà
        existing_admin = db.query(AdministrateurDB).filter(AdministrateurDB.username == username).first()
        existing_prof = db.query(ProfesseurDB).filter(ProfesseurDB.username == username).first()
        existing_etudiant = db.query(EtudiantDB).filter(EtudiantDB.username == username).first()
        
        if existing_admin or existing_prof or existing_etudiant:
            return RedirectResponse("/dashboard/admin?error=Ce nom d'utilisateur existe déjà", status_code=303)
        
        # Vérifier que l'université existe
        universite = db.query(UniversiteDB).filter(UniversiteDB.id == universite_id).first()
        if not universite:
            return RedirectResponse("/dashboard/admin?error=Université invalide", status_code=303)
        
        # Créer le nouvel administrateur
        new_admin = AdministrateurDB(
            username=username,
            password_hash=hash_password(password),
            nom=nom,
            prenom=prenom,
            is_main_admin=False,
            universite_id=universite_id
        )
        
        db.add(new_admin)
        db.commit()
        return RedirectResponse("/dashboard/admin?success=Administrateur créé avec succès", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la création: {str(e)}", status_code=303)

@app.post("/admin/create-prof")
async def admin_create_prof(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    nom: str = Form(...),
    prenom: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    specialite: str = Form(...),
    universite_id: str = Form(...),
    ufr_id: str = Form(...),
    filiere_id: str = Form(...),
    matiere_id: str = Form(...),
    db: Session = Depends(get_db)
):
    """Admin creates new professor with hierarchical structure"""
    admin_username, admin_data = admin_info
    
    try:
        # Check if username already exists
        existing_admin = db.query(AdministrateurDB).filter(AdministrateurDB.username == username).first()
        existing_prof = db.query(ProfesseurDB).filter(ProfesseurDB.username == username).first()
        existing_etudiant = db.query(EtudiantDB).filter(EtudiantDB.username == username).first()
        
        if existing_admin or existing_prof or existing_etudiant:
            return RedirectResponse(url="/dashboard/admin?error=Ce nom d'utilisateur existe déjà", status_code=303)
        
        # Validate hierarchical relationships
        universite = db.query(UniversiteDB).filter(UniversiteDB.id == universite_id).first()
        if not universite:
            return RedirectResponse(url="/dashboard/admin?error=Université non trouvée", status_code=303)
        
        ufr = db.query(UFRDB).filter(UFRDB.id == ufr_id, UFRDB.universite_id == universite_id).first()
        if not ufr:
            return RedirectResponse(url="/dashboard/admin?error=UFR non valide pour cette université", status_code=303)
        
        filiere = db.query(FiliereDB).filter(FiliereDB.id == filiere_id, FiliereDB.ufr_id == ufr_id).first()
        if not filiere:
            return RedirectResponse(url="/dashboard/admin?error=Filière non valide pour cette UFR", status_code=303)
        
        matiere = db.query(MatiereDB).filter(MatiereDB.id == matiere_id, MatiereDB.filiere_id == filiere_id).first()
        if not matiere:
            return RedirectResponse(url="/dashboard/admin?error=Matière non valide pour cette filière", status_code=303)
        
        # Create new professor with hierarchical structure
        new_prof = ProfesseurDB(
            username=username,
            password_hash=hash_password(password),
            nom=nom,
            prenom=prenom,
            specialite=specialite,
            universite_id=universite_id,
            ufr_id=ufr_id,
            filiere_id=filiere_id,
            matiere_id=matiere_id,
            matiere=matiere.nom
        )
        
        db.add(new_prof)
        db.commit()
        return RedirectResponse(url="/dashboard/admin?success=Professeur créé avec succès", status_code=303)
        
    except Exception as e:
        db.rollback()
        return RedirectResponse(url=f"/dashboard/admin?error=Erreur lors de la création: {str(e)}", status_code=303)

@app.post("/admin/create-universite")
async def admin_create_universite(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    nom: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    """Admin creates new university (main admin only)"""
    admin_username, admin_data = admin_info
    
    # Vérifier que seul l'admin principal peut créer des universités
    if not admin_data.get("is_main_admin", False):
        return RedirectResponse(url="/dashboard/admin?error=Seul l'administrateur principal peut créer des universités", status_code=303)
    
    try:
        # Check if code already exists
        existing_universite = db.query(UniversiteDB).filter(UniversiteDB.code == code).first()
        if existing_universite:
            return RedirectResponse(url="/dashboard/admin?error=Code université déjà existant", status_code=303)
        
        # Create new university
        new_universite = UniversiteDB(
            id=str(uuid.uuid4()),
            nom=nom,
            code=code,
            logo_url=None
        )
        
        db.add(new_universite)
        db.commit()
        return RedirectResponse(url="/dashboard/admin?success=Université créée avec succès", status_code=303)
        
    except Exception as e:
        db.rollback()
        return RedirectResponse(url=f"/dashboard/admin?error=Erreur lors de la création: {str(e)}", status_code=303)

@app.post("/admin/create-ufr")
async def admin_create_ufr(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    nom: str = Form(...),
    code: str = Form(...),
    universite_id: str = Form(...),
    db: Session = Depends(get_db)
):
    """Admin creates new UFR"""
    admin_username, admin_data = admin_info
    
    # Vérifier que l'admin secondaire crée l'UFR dans son université uniquement
    if not admin_data.get("is_main_admin", False):
        if admin_data.get("universite_id") != universite_id:
            return RedirectResponse(url="/dashboard/admin?error=Vous ne pouvez créer des UFR que dans votre université", status_code=303)
    
    try:
        # Check if university exists
        universite = db.query(UniversiteDB).filter(UniversiteDB.id == universite_id).first()
        if not universite:
            return RedirectResponse(url="/dashboard/admin?error=Université non trouvée", status_code=303)
        
        # Check if code already exists for this university
        existing_ufr = db.query(UFRDB).filter(
            UFRDB.code == code, 
            UFRDB.universite_id == universite_id
        ).first()
        if existing_ufr:
            return RedirectResponse(url="/dashboard/admin?error=Code UFR déjà existant pour cette université", status_code=303)
        
        # Create new UFR
        new_ufr = UFRDB(
            id=str(uuid.uuid4()),
            nom=nom,
            code=code,
            universite_id=universite_id
        )
        
        db.add(new_ufr)
        db.commit()
        return RedirectResponse(url="/dashboard/admin?success=UFR créée avec succès", status_code=303)
        
    except Exception as e:
        db.rollback()
        return RedirectResponse(url=f"/dashboard/admin?error=Erreur lors de la création: {str(e)}", status_code=303)


@app.post("/admin/create-filiere")
async def admin_create_filiere(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    nom: str = Form(...),
    code: str = Form(...),
    ufr_id: str = Form(...),
    db: Session = Depends(get_db)
):
    """Admin creates new filière"""
    admin_username, admin_data = admin_info
    
    try:
        # Check if UFR exists
        ufr = db.query(UFRDB).filter(UFRDB.id == ufr_id).first()
        if not ufr:
            return RedirectResponse(url="/dashboard/admin?error=UFR non trouvée", status_code=303)
        
        # Vérifier que l'admin secondaire crée la filière dans une UFR de son université
        if not admin_data.get("is_main_admin", False):
            if ufr.universite_id != admin_data.get("universite_id"):
                return RedirectResponse(url="/dashboard/admin?error=Vous ne pouvez créer des filières que dans votre université", status_code=303)
        
        # Check if code already exists for this UFR
        existing_filiere = db.query(FiliereDB).filter(
            FiliereDB.code == code, 
            FiliereDB.ufr_id == ufr_id
        ).first()
        if existing_filiere:
            return RedirectResponse(url="/dashboard/admin?error=Code filière déjà existant pour cette UFR", status_code=303)
        
        # Create new filiere
        new_filiere = FiliereDB(
            id=str(uuid.uuid4()),
            nom=nom,
            code=code,
            ufr_id=ufr_id
        )
        
        db.add(new_filiere)
        db.commit()
        return RedirectResponse(url="/dashboard/admin?success=Filière créée avec succès", status_code=303)
        
    except Exception as e:
        db.rollback()
        return RedirectResponse(url=f"/dashboard/admin?error=Erreur lors de la création: {str(e)}", status_code=303)


@app.post("/admin/create-matiere")
async def admin_create_matiere(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    nom: str = Form(...),
    code: str = Form(...),
    filiere_id: str = Form(...),
    db: Session = Depends(get_db)
):
    """Admin creates new matière"""
    admin_username, admin_data = admin_info
    
    try:
        # Check if filiere exists
        filiere = db.query(FiliereDB).filter(FiliereDB.id == filiere_id).first()
        if not filiere:
            return RedirectResponse(url="/dashboard/admin?error=Filière non trouvée", status_code=303)
        
        # Vérifier que l'admin secondaire crée la matière dans une filière de son université
        if not admin_data.get("is_main_admin", False):
            # Récupérer l'UFR de la filière
            ufr = db.query(UFRDB).filter(UFRDB.id == filiere.ufr_id).first()
            if ufr and ufr.universite_id != admin_data.get("universite_id"):
                return RedirectResponse(url="/dashboard/admin?error=Vous ne pouvez créer des matières que dans votre université", status_code=303)
        
        # Check if code already exists for this filiere
        existing_matiere = db.query(MatiereDB).filter(
            MatiereDB.code == code, 
            MatiereDB.filiere_id == filiere_id
        ).first()
        if existing_matiere:
            return RedirectResponse(url="/dashboard/admin?error=Code matière déjà existant pour cette filière", status_code=303)
        
        # Create new matiere
        new_matiere = MatiereDB(
            id=str(uuid.uuid4()),
            nom=nom,
            code=code,
            filiere_id=filiere_id
        )
        
        db.add(new_matiere)
        db.commit()
        return RedirectResponse(url="/dashboard/admin?success=Matière créée avec succès", status_code=303)
        
    except Exception as e:
        db.rollback()
        return RedirectResponse(url=f"/dashboard/admin?error=Erreur lors de la création: {str(e)}", status_code=303)


# Routes pour modification et suppression

# Admin routes
@app.post("/admin/edit-admin")
async def admin_edit_admin(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    username: str = Form(...),
    nom: str = Form(...),
    prenom: str = Form(...),
    db: Session = Depends(get_db)
):
    """Edit administrator (only for principal admin)"""

    admin_username, admin_data = admin_info
    
    # Vérifier que seul l'admin principal peut modifier des admins
    if not admin_data.get("is_main_admin", False):
        return RedirectResponse("/dashboard/admin?error=Seul l'administrateur principal peut modifier des administrateurs", status_code=303)
    
    try:
        admin = db.query(AdministrateurDB).filter(AdministrateurDB.username == username).first()
        if admin:
            admin.nom = nom
            admin.prenom = prenom
            db.commit()
            return RedirectResponse("/dashboard/admin?success=Administrateur modifié avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Administrateur non trouvé", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la modification: {str(e)}", status_code=303)


@app.post("/admin/delete-admin")
async def admin_delete_admin(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    username: str = Form(...),
    db: Session = Depends(get_db)
):
    """Delete administrator (only for principal admin)"""

    admin_username, admin_data = admin_info
    
    # Vérifier que seul l'admin principal peut supprimer des admins
    if not admin_data.get("is_main_admin", False):
        return RedirectResponse("/dashboard/admin?error=Seul l'administrateur principal peut supprimer des administrateurs", status_code=303)
    
    # L'admin principal ne peut pas être supprimé
    if username == "maodoka65":
        return RedirectResponse("/dashboard/admin?error=L'administrateur principal ne peut pas être supprimé", status_code=303)
    
    try:
        admin = db.query(AdministrateurDB).filter(AdministrateurDB.username == username).first()
        if admin:
            db.delete(admin)
            db.commit()
            return RedirectResponse("/dashboard/admin?success=Administrateur supprimé avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Administrateur non trouvé", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)


@app.post("/admin/toggle-admin-status")
async def admin_toggle_status(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    username: str = Form(...),
    db: Session = Depends(get_db)
):
    """Toggle administrator active status (only for principal admin) - Returns JSON"""
    from fastapi.responses import JSONResponse

    admin_username, admin_data = admin_info
    
    # Vérifier que seul l'admin principal peut activer/désactiver des admins
    if not admin_data.get("is_main_admin", False):
        return JSONResponse(
            status_code=403,
            content={"success": False, "error": "Seul l'administrateur principal peut activer/désactiver des administrateurs"}
        )
    
    # L'admin principal ne peut pas être désactivé
    admin = db.query(AdministrateurDB).filter(AdministrateurDB.username == username).first()
    if admin and admin.is_main_admin:
        return JSONResponse(
            status_code=400,
            content={"success": False, "error": "L'administrateur principal ne peut pas être désactivé"}
        )
    
    try:
        if admin:
            # Toggle le statut actif
            admin.actif = not admin.actif
            db.commit()
            status_text = "activé" if admin.actif else "désactivé"
            return JSONResponse(
                status_code=200,
                content={"success": True, "message": f"Administrateur {status_text} avec succès", "new_status": admin.actif}
            )
        else:
            return JSONResponse(
                status_code=404,
                content={"success": False, "error": "Administrateur non trouvé"}
            )
    except Exception as e:
        db.rollback()
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"Erreur lors du changement de statut: {str(e)}"}
        )


@app.post("/admin/toggle-prof-status")
async def admin_toggle_prof_status(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    username: str = Form(...),
    db: Session = Depends(get_db)
):
    """Toggle professor active status (only for principal admin) - Returns JSON"""
    from fastapi.responses import JSONResponse

    admin_username, admin_data = admin_info
    
    # Vérifier que seul l'admin principal peut activer/désactiver des profs
    if not admin_data.get("is_main_admin", False):
        return JSONResponse(
            status_code=403,
            content={"success": False, "error": "Seul l'administrateur principal peut activer/désactiver des professeurs"}
        )
    
    try:
        prof = db.query(ProfesseurDB).filter(ProfesseurDB.username == username).first()
        if prof:
            # Toggle le statut actif
            prof.actif = not prof.actif
            db.commit()
            status_text = "activé" if prof.actif else "désactivé"
            return JSONResponse(
                status_code=200,
                content={"success": True, "message": f"Professeur {status_text} avec succès", "new_status": prof.actif}
            )
        else:
            return JSONResponse(
                status_code=404,
                content={"success": False, "error": "Professeur non trouvé"}
            )
    except Exception as e:
        db.rollback()
        return JSONResponse(
            status_code=500,
            content={"success": False, "error": f"Erreur lors du changement de statut: {str(e)}"}
        )


# Professor routes
@app.post("/admin/edit-prof")
async def admin_edit_prof(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    username: str = Form(...),
    nom: str = Form(...),
    prenom: str = Form(...),
    specialite: str = Form(...),
    db: Session = Depends(get_db)
):
    """Edit professor"""

    admin_username, admin_data = admin_info
    
    try:
        prof = db.query(ProfesseurDB).filter(ProfesseurDB.username == username).first()
        if prof:
            prof.nom = nom
            prof.prenom = prenom
            prof.specialite = specialite
            db.commit()
            return RedirectResponse("/dashboard/admin?success=Professeur modifié avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Professeur non trouvé", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la modification: {str(e)}", status_code=303)


@app.post("/admin/delete-prof")
async def admin_delete_prof(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    username: str = Form(...),
    db: Session = Depends(get_db)
):
    """Delete professor and all their content"""

    admin_username, admin_data = admin_info
    
    try:
        prof = db.query(ProfesseurDB).filter(ProfesseurDB.username == username).first()
        if prof:
            # Supprimer d'abord tout le contenu créé par ce professeur
            chapitres = db.query(ChapitreCompletDB).filter(ChapitreCompletDB.created_by == username).all()
            for chapitre in chapitres:
                db.delete(chapitre)
            
            # Puis supprimer le professeur
            db.delete(prof)
            db.commit()
            return RedirectResponse("/dashboard/admin?success=Professeur et son contenu supprimés avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Professeur non trouvé", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)


# Student routes
@app.post("/admin/delete-etudiant")
async def admin_delete_etudiant(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    username: str = Form(...),
    db: Session = Depends(get_db)
):
    """Delete student"""

    admin_username, admin_data = admin_info
    
    try:
        etudiant = db.query(EtudiantDB).filter(EtudiantDB.username == username).first()
        if etudiant:
            db.delete(etudiant)
            db.commit()
            return RedirectResponse("/dashboard/admin?success=Étudiant supprimé avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Étudiant non trouvé", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)

# University routes
@app.post("/admin/edit-universite")
async def admin_edit_universite(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...),
    nom: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    """Edit university (main admin only)"""

    admin_username, admin_data = admin_info
    
    # Vérifier que seul l'admin principal peut modifier des universités
    if not admin_data.get("is_main_admin", False):
        return RedirectResponse("/dashboard/admin?error=Seul l'administrateur principal peut modifier des universités", status_code=303)
    
    try:
        universite = db.query(UniversiteDB).filter(UniversiteDB.id == id).first()
        if universite:
            universite.nom = nom
            universite.code = code
            db.commit()
            return RedirectResponse("/dashboard/admin?success=Université modifiée avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Université non trouvée", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la modification: {str(e)}", status_code=303)


@app.post("/admin/delete-universite")
async def admin_delete_universite(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...),
    db: Session = Depends(get_db)
):
    """Delete university and all related data (main admin only)"""

    admin_username, admin_data = admin_info
    
    # Vérifier que seul l'admin principal peut supprimer des universités
    if not admin_data.get("is_main_admin", False):
        return RedirectResponse("/dashboard/admin?error=Seul l'administrateur principal peut supprimer des universités", status_code=303)
    
    try:
        universite = db.query(UniversiteDB).filter(UniversiteDB.id == id).first()
        if universite:
            # Supprimer tous les chapitres des professeurs de cette université
            profs_universite = db.query(ProfesseurDB).filter(ProfesseurDB.universite_id == id).all()
            for prof in profs_universite:
                chapitres = db.query(ChapitreCompletDB).filter(ChapitreCompletDB.created_by == prof.username).all()
                for chapitre in chapitres:
                    db.delete(chapitre)
            
            # Supprimer tous les professeurs de cette université
            db.query(ProfesseurDB).filter(ProfesseurDB.universite_id == id).delete()
            
            # Supprimer tous les étudiants liés aux filières de cette université
            ufrs = db.query(UFRDB).filter(UFRDB.universite_id == id).all()
            for ufr in ufrs:
                filieres = db.query(FiliereDB).filter(FiliereDB.ufr_id == ufr.id).all()
                for filiere in filieres:
                    # Supprimer les étudiants de cette filière
                    db.query(EtudiantDB).filter(EtudiantDB.filiere_id == filiere.id).delete()
                    # Supprimer les matières de cette filière
                    db.query(MatiereDB).filter(MatiereDB.filiere_id == filiere.id).delete()
                # Supprimer les filières de cet UFR
                db.query(FiliereDB).filter(FiliereDB.ufr_id == ufr.id).delete()
            
            # Supprimer tous les UFR de cette université
            db.query(UFRDB).filter(UFRDB.universite_id == id).delete()
            
            # Supprimer l'université
            db.delete(universite)
            db.commit()
            return RedirectResponse("/dashboard/admin?success=Université et toutes ses données supprimées avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Université non trouvée", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)


# UFR routes
@app.post("/admin/edit-ufr")
async def admin_edit_ufr(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...),
    nom: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    """Edit UFR"""

    admin_username, admin_data = admin_info
    
    try:
        ufr = db.query(UFRDB).filter(UFRDB.id == id).first()
        if not ufr:
            return RedirectResponse("/dashboard/admin?error=UFR non trouvée", status_code=303)
        
        # Vérifier que l'admin secondaire modifie une UFR de son université
        if not admin_data.get("is_main_admin", False):
            if ufr.universite_id != admin_data.get("universite_id"):
                return RedirectResponse("/dashboard/admin?error=Vous ne pouvez modifier que les UFR de votre université", status_code=303)
        
        ufr.nom = nom
        ufr.code = code
        db.commit()
        return RedirectResponse("/dashboard/admin?success=UFR modifiée avec succès", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la modification: {str(e)}", status_code=303)


@app.post("/admin/delete-ufr")
async def admin_delete_ufr(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...),
    db: Session = Depends(get_db)
):
    """Delete UFR and all related data"""

    admin_username, admin_data = admin_info
    
    try:
        ufr = db.query(UFRDB).filter(UFRDB.id == id).first()
        if not ufr:
            return RedirectResponse("/dashboard/admin?error=UFR non trouvée", status_code=303)
        
        # Vérifier que l'admin secondaire supprime une UFR de son université
        if not admin_data.get("is_main_admin", False):
            if ufr.universite_id != admin_data.get("universite_id"):
                return RedirectResponse("/dashboard/admin?error=Vous ne pouvez supprimer que les UFR de votre université", status_code=303)
        
        if ufr:
            # Supprimer tous les chapitres des professeurs de cet UFR
            profs_ufr = db.query(ProfesseurDB).filter(ProfesseurDB.ufr_id == id).all()
            for prof in profs_ufr:
                chapitres = db.query(ChapitreCompletDB).filter(ChapitreCompletDB.created_by == prof.username).all()
                for chapitre in chapitres:
                    db.delete(chapitre)
            
            # Supprimer tous les professeurs de cet UFR
            db.query(ProfesseurDB).filter(ProfesseurDB.ufr_id == id).delete()
            
            # Supprimer tous les étudiants et matières liés aux filières de cet UFR
            filieres = db.query(FiliereDB).filter(FiliereDB.ufr_id == id).all()
            for filiere in filieres:
                # Supprimer les étudiants de cette filière
                db.query(EtudiantDB).filter(EtudiantDB.filiere_id == filiere.id).delete()
                # Supprimer les matières de cette filière
                db.query(MatiereDB).filter(MatiereDB.filiere_id == filiere.id).delete()
            
            # Supprimer toutes les filières de cet UFR
            db.query(FiliereDB).filter(FiliereDB.ufr_id == id).delete()
            
            # Supprimer l'UFR
            db.delete(ufr)
            db.commit()
            return RedirectResponse("/dashboard/admin?success=UFR et toutes ses données supprimées avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=UFR non trouvée", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)


# Filière routes
@app.post("/admin/edit-filiere")
async def admin_edit_filiere(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...),
    nom: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    """Edit filière"""

    admin_username, admin_data = admin_info
    
    try:
        filiere = db.query(FiliereDB).filter(FiliereDB.id == id).first()
        if not filiere:
            return RedirectResponse("/dashboard/admin?error=Filière non trouvée", status_code=303)
        
        # Vérifier que l'admin secondaire modifie une filière de son université
        if not admin_data.get("is_main_admin", False):
            ufr = db.query(UFRDB).filter(UFRDB.id == filiere.ufr_id).first()
            if ufr and ufr.universite_id != admin_data.get("universite_id"):
                return RedirectResponse("/dashboard/admin?error=Vous ne pouvez modifier que les filières de votre université", status_code=303)
        
        filiere.nom = nom
        filiere.code = code
        db.commit()
        return RedirectResponse("/dashboard/admin?success=Filière modifiée avec succès", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la modification: {str(e)}", status_code=303)


@app.post("/admin/delete-filiere")
async def admin_delete_filiere(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...),
    db: Session = Depends(get_db)
):
    """Delete filière and all related data"""

    admin_username, admin_data = admin_info
    
    try:
        filiere = db.query(FiliereDB).filter(FiliereDB.id == id).first()
        if not filiere:
            return RedirectResponse("/dashboard/admin?error=Filière non trouvée", status_code=303)
        
        # Vérifier que l'admin secondaire supprime une filière de son université
        if not admin_data.get("is_main_admin", False):
            ufr = db.query(UFRDB).filter(UFRDB.id == filiere.ufr_id).first()
            if ufr and ufr.universite_id != admin_data.get("universite_id"):
                return RedirectResponse("/dashboard/admin?error=Vous ne pouvez supprimer que les filières de votre université", status_code=303)
        
        if filiere:
            # Supprimer tous les chapitres des professeurs de cette filière
            profs_filiere = db.query(ProfesseurDB).filter(ProfesseurDB.filiere_id == id).all()
            for prof in profs_filiere:
                chapitres = db.query(ChapitreCompletDB).filter(ChapitreCompletDB.created_by == prof.username).all()
                for chapitre in chapitres:
                    db.delete(chapitre)
            
            # Supprimer tous les professeurs de cette filière
            db.query(ProfesseurDB).filter(ProfesseurDB.filiere_id == id).delete()
            
            # Supprimer tous les étudiants de cette filière
            db.query(EtudiantDB).filter(EtudiantDB.filiere_id == id).delete()
            
            # Supprimer toutes les matières de cette filière
            db.query(MatiereDB).filter(MatiereDB.filiere_id == id).delete()
            
            # Supprimer la filière
            db.delete(filiere)
            db.commit()
            return RedirectResponse("/dashboard/admin?success=Filière et toutes ses données supprimées avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Filière non trouvée", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)


# Matière routes
@app.post("/admin/edit-matiere")
async def admin_edit_matiere(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...),
    nom: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    """Edit matière"""

    admin_username, admin_data = admin_info
    
    try:
        matiere = db.query(MatiereDB).filter(MatiereDB.id == id).first()
        if not matiere:
            return RedirectResponse("/dashboard/admin?error=Matière non trouvée", status_code=303)
        
        # Vérifier que l'admin secondaire modifie une matière de son université
        if not admin_data.get("is_main_admin", False):
            filiere = db.query(FiliereDB).filter(FiliereDB.id == matiere.filiere_id).first()
            if filiere:
                ufr = db.query(UFRDB).filter(UFRDB.id == filiere.ufr_id).first()
                if ufr and ufr.universite_id != admin_data.get("universite_id"):
                    return RedirectResponse("/dashboard/admin?error=Vous ne pouvez modifier que les matières de votre université", status_code=303)
        
        matiere.nom = nom
        matiere.code = code
        db.commit()
        return RedirectResponse("/dashboard/admin?success=Matière modifiée avec succès", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la modification: {str(e)}", status_code=303)


@app.post("/admin/delete-matiere")
async def admin_delete_matiere(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...),
    db: Session = Depends(get_db)
):
    """Delete matière and all related content"""

    admin_username, admin_data = admin_info
    
    try:
        matiere = db.query(MatiereDB).filter(MatiereDB.id == id).first()
        if not matiere:
            return RedirectResponse("/dashboard/admin?error=Matière non trouvée", status_code=303)
        
        # Vérifier que l'admin secondaire supprime une matière de son université
        if not admin_data.get("is_main_admin", False):
            filiere = db.query(FiliereDB).filter(FiliereDB.id == matiere.filiere_id).first()
            if filiere:
                ufr = db.query(UFRDB).filter(UFRDB.id == filiere.ufr_id).first()
                if ufr and ufr.universite_id != admin_data.get("universite_id"):
                    return RedirectResponse("/dashboard/admin?error=Vous ne pouvez supprimer que les matières de votre université", status_code=303)
        
        # PostgreSQL s'occupera des suppressions en cascade
        db.delete(matiere)
        db.commit()
        return RedirectResponse("/dashboard/admin?success=Matière et son contenu supprimés avec succès", status_code=303)
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)


# Route pour upload de logo université
@app.post("/admin/upload-logo")
async def admin_upload_logo(
    request: Request,
    admin_username: str = Depends(require_admin),
    universite_id: str = Form(...),
    logo: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    """Admin uploads logo for university"""
    try:
        # Validate file type
        if not logo.content_type.startswith('image/'):
            return RedirectResponse("/dashboard/admin?error=Le fichier doit être une image", status_code=303)
        
        # Save file with unique name
        file_extension = logo.filename.split('.')[-1]
        unique_filename = f"logo_universite_{universite_id}_{uuid.uuid4().hex[:8]}.{file_extension}"
        file_path = f"static/{unique_filename}"
        
        # Create static directory if it doesn't exist
        os.makedirs("static", exist_ok=True)
        
        # Save file
        with open(file_path, "wb") as f:
            content = await logo.read()
            f.write(content)
        
        # Update database (PostgreSQL)
        universite = db.query(UniversiteDB).filter_by(id=universite_id).first()
        if universite:
            # Remove old logo file if exists
            if universite.logo_url and universite.logo_url.startswith("/static/"):
                old_file_path = universite.logo_url[1:]  # Remove leading slash
                if os.path.exists(old_file_path):
                    os.remove(old_file_path)
            
            universite.logo_url = f"/{file_path}"
            db.commit()
        
        return RedirectResponse("/dashboard/admin?success=Logo téléchargé avec succès", status_code=303)
        
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors du téléchargement: {str(e)}", status_code=303)

# Routes pour les professeurs - modification et suppression de chapitres
@app.post("/prof/edit-chapitre")
async def prof_edit_chapitre(
    request: Request,
    prof_username: str = Depends(require_prof),
    chapitre_id: str = Form(...),
    nouveau_titre: str = Form(...),
    db: Session = Depends(get_db)
):
    """Professor edits their chapter title"""
    try:
        # Find the chapter and verify ownership
        chapitre = db.query(ChapitreCompletDB).filter_by(
            id=chapitre_id,
            created_by=prof_username
        ).first()
        
        if not chapitre:
            return RedirectResponse("/dashboard/prof?error=Chapitre non trouvé ou accès non autorisé", status_code=303)
        
        chapitre.titre = nouveau_titre
        db.commit()
        return RedirectResponse("/dashboard/prof?success=Chapitre modifié avec succès", status_code=303)
    
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/prof?error=Erreur lors de la modification: {str(e)}", status_code=303)

@app.post("/prof/delete-chapitre")
async def prof_delete_chapitre(
    request: Request,
    prof_data: Tuple[str, Dict[str, Any]] = Depends(require_prof),
    chapitre_id: str = Form(...),
    db: Session = Depends(get_db)
):
    """Professor deletes their chapter"""
    try:
        prof_username, prof_data = prof_data
        # Find the chapter and verify ownership
        chapitre = db.query(ChapitreCompletDB).filter_by(
            id=chapitre_id,
            created_by=prof_username
        ).first()
        
        if not chapitre:
            return RedirectResponse("/dashboard/prof?error=Chapitre non trouvé ou accès non autorisé", status_code=303)
        
        # Delete chapter from PostgreSQL
        db.delete(chapitre)
        db.commit()
        return RedirectResponse("/dashboard/prof?success=Chapitre supprimé avec succès", status_code=303)
    
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/prof?error=Erreur lors de la suppression: {str(e)}", status_code=303)

@app.post("/prof/modifier-chapitre-complet")
async def modifier_chapitre_complet(
    request: Request,
    prof_data: Tuple[str, Dict[str, Any]] = Depends(require_prof),
    chapitre_id: str = Form(...),
    titre: str = Form(...),
    cours_texte: str = Form(""),
    exercice_texte: str = Form(""),
    solution_texte: str = Form(""),
    db: Session = Depends(get_db)
):
    """Modify complete chapter with all content (text and files)"""
    prof_username, prof_user_data = prof_data
    
    try:
        # Find the chapter and verify ownership
        chapitre = db.query(ChapitreCompletDB).filter_by(
            id=chapitre_id,
            created_by=prof_username
        ).first()
        
        if not chapitre:
            return RedirectResponse("/dashboard/prof?error=Chapitre non trouvé ou accès non autorisé", status_code=303)
        
        # Récupérer tous les fichiers uploadés via le formulaire
        form_data = await request.form()
        
        # Collecter les fichiers pour chaque section
        cours_files = []
        exercice_files = []
        solution_files = []
        
        for key, value in form_data.items():
            if key.startswith('cours_fichier') and hasattr(value, 'filename') and value.filename:
                cours_files.append(value)
            elif key.startswith('exercice_fichier') and hasattr(value, 'filename') and value.filename:
                exercice_files.append(value)
            elif key.startswith('solution_fichier') and hasattr(value, 'filename') and value.filename:
                solution_files.append(value)
        
        # Helper function to save multiple files
        async def save_files(files: list, type_folder: str) -> tuple[str, str]:
            """Save multiple files and return names and paths separated by |||"""
            if not files or len(files) == 0:
                return None, None
            
            upload_dir = Path("uploads") / type_folder
            upload_dir.mkdir(parents=True, exist_ok=True)
            
            file_names = []
            file_paths = []
            
            for file in files:
                if not file or not file.filename:
                    continue
                    
                file_extension = Path(file.filename).suffix
                unique_filename = f"{uuid.uuid4()}{file_extension}"
                file_path = upload_dir / unique_filename
                
                try:
                    content = await file.read()
                    with open(file_path, "wb") as f:
                        f.write(content)
                    file_names.append(file.filename)
                    file_paths.append(str(file_path))
                except Exception as e:
                    raise HTTPException(status_code=500, detail=f"Erreur upload {type_folder}: {str(e)}")
            
            if len(file_names) == 0:
                return None, None
                
            # Join with ||| separator
            return "|||".join(file_names), "|||".join(file_paths)
        
        # Update title
        chapitre.titre = titre
        
        # Update text content
        chapitre.cours_texte = cours_texte
        chapitre.exercice_texte = exercice_texte
        chapitre.solution_texte = solution_texte
        
        # Update files if new ones are provided
        if cours_files:
            cours_nom, cours_path = await save_files(cours_files, "cours")
            if cours_nom and cours_path:
                chapitre.cours_fichier_nom = cours_nom
                chapitre.cours_fichier_path = cours_path
        
        if exercice_files:
            exercice_nom, exercice_path = await save_files(exercice_files, "exercices")
            if exercice_nom and exercice_path:
                chapitre.exercice_fichier_nom = exercice_nom
                chapitre.exercice_fichier_path = exercice_path
        
        if solution_files:
            solution_nom, solution_path = await save_files(solution_files, "solutions")
            if solution_nom and solution_path:
                chapitre.solution_fichier_nom = solution_nom
                chapitre.solution_fichier_path = solution_path
        
        # Validate that each section still has at least text or file
        errors = []
        if not chapitre.cours_texte.strip() and not chapitre.cours_fichier_nom:
            errors.append("Cours: vous devez avoir soit du texte soit un fichier")
        
        if not chapitre.exercice_texte.strip() and not chapitre.exercice_fichier_nom:
            errors.append("Exercices: vous devez avoir soit du texte soit un fichier")
            
        if not chapitre.solution_texte.strip() and not chapitre.solution_fichier_nom:
            errors.append("Solutions: vous devez avoir soit du texte soit un fichier")
        
        if errors:
            db.rollback()
            error_msg = " | ".join(errors)
            return RedirectResponse(url=f"/dashboard/prof?error={error_msg}", status_code=303)
        
        db.commit()
        return RedirectResponse("/dashboard/prof?success=Chapitre modifié avec succès", status_code=303)
    
    except Exception as e:
        db.rollback()
        return RedirectResponse(f"/dashboard/prof?error=Erreur lors de la modification: {str(e)}", status_code=303)

# API endpoints for hierarchical data

@app.get("/api/chapitres/hierarchy")
async def get_chapitres_hierarchy(request: Request, db: Session = Depends(get_db)):
    """Get chapters organized hierarchically: Niveau → Matière → Semestre → Chapitre"""
    try:
        role, username, user_data = require_auth(request, db)
    except HTTPException:
        raise HTTPException(status_code=401, detail="Authentication required")
    
    # Get all necessary academic data
    matieres = db.query(MatiereDB).all()
    
    # Filter chapters based on role
    if role == "etudiant":
        # Student: get chapters from their filière (all levels)
        etudiant = db.query(EtudiantDB).filter_by(username=username).first()
        if not etudiant:
            return {"hierarchy": []}
        
        chapitres = db.query(ChapitreCompletDB).filter(
            ChapitreCompletDB.filiere_id == etudiant.filiere_id
        ).all()
    elif role == "prof":
        # Professor: get chapters from their subject
        prof = db.query(ProfesseurDB).filter_by(username=username).first()
        if not prof:
            return {"hierarchy": []}
        
        # Get professor's matière_id
        if not prof.matiere_id:
            return {"hierarchy": []}
        
        chapitres = db.query(ChapitreCompletDB).filter(
            ChapitreCompletDB.matiere_id == prof.matiere_id
        ).all()
    else:
        return {"hierarchy": []}
    
    # Build hierarchy: Niveau → Matière → Semestre → Chapitre
    hierarchy_dict = {}
    
    for chapitre in chapitres:
        # Get matière name
        matiere_obj = next((m for m in matieres if m.id == chapitre.matiere_id), None)
        matiere_nom = matiere_obj.nom if matiere_obj else "Matière inconnue"
        
        # Initialize niveau if not exists
        if chapitre.niveau not in hierarchy_dict:
            hierarchy_dict[chapitre.niveau] = {}
        
        # Initialize matière if not exists
        if matiere_nom not in hierarchy_dict[chapitre.niveau]:
            hierarchy_dict[chapitre.niveau][matiere_nom] = {
                "matiere_id": chapitre.matiere_id,
                "matiere_nom": matiere_nom,
                "semestres": {}
            }
        
        # Initialize semestre if not exists
        semestre_key = f"Semestre {chapitre.semestre}"
        if semestre_key not in hierarchy_dict[chapitre.niveau][matiere_nom]["semestres"]:
            hierarchy_dict[chapitre.niveau][matiere_nom]["semestres"][semestre_key] = []
        
        # Add chapter
        hierarchy_dict[chapitre.niveau][matiere_nom]["semestres"][semestre_key].append({
            "id": chapitre.id,
            "numero": chapitre.chapitre,
            "titre": chapitre.titre,
            "cours_texte": chapitre.cours_texte or "",
            "cours_fichier_nom": chapitre.cours_fichier_nom,
            "cours_fichier_path": chapitre.cours_fichier_path,
            "exercice_texte": chapitre.exercice_texte or "",
            "exercice_fichier_nom": chapitre.exercice_fichier_nom,
            "exercice_fichier_path": chapitre.exercice_fichier_path,
            "solution_texte": chapitre.solution_texte or "",
            "solution_fichier_nom": chapitre.solution_fichier_nom,
            "solution_fichier_path": chapitre.solution_fichier_path,
            "created_by": chapitre.created_by
        })
    
    # Convert to sorted list structure
    hierarchy = []
    
    # Sort levels (L1, L2, L3, M1, M2)
    niveau_order = ["L1", "L2", "L3", "M1", "M2"]
    for niveau in sorted(hierarchy_dict.keys(), key=lambda x: niveau_order.index(x) if x in niveau_order else 99):
        matieres_list = []
        
        # Sort matières alphabetically
        for matiere_nom in sorted(hierarchy_dict[niveau].keys()):
            matiere_data = hierarchy_dict[niveau][matiere_nom]
            semestres_list = []
            
            # Sort semesters (Semestre 1, Semestre 2, etc.)
            def get_semester_num(s):
                parts = s.split()
                if len(parts) > 1:
                    # Extract number from "Semestre 1" or similar
                    num_part = parts[1].replace('S', '').replace('s', '')
                    try:
                        return int(num_part)
                    except:
                        return 0
                return 0
            
            for sem_key in sorted(matiere_data["semestres"].keys(), key=get_semester_num):
                # Sort chapters by numero
                chapters_sorted = sorted(matiere_data["semestres"][sem_key], key=lambda x: int(x["numero"]) if str(x["numero"]).isdigit() else 0)
                semestres_list.append({
                    "semestre": sem_key,
                    "chapitres": chapters_sorted
                })
            
            matieres_list.append({
                "matiere_id": matiere_data["matiere_id"],
                "matiere_nom": matiere_data["matiere_nom"],
                "semestres": semestres_list
            })
        
        hierarchy.append({
            "niveau": niveau,
            "matieres": matieres_list
        })
    
    return {"hierarchy": hierarchy, "role": role}

@app.get("/api/ufrs/{universite_id}")
async def get_ufrs_api(universite_id: str, db: Session = Depends(get_db)):
    """Get UFRs for a specific university"""
    ufrs = get_ufrs_by_universite(db, universite_id)
    return {"ufrs": ufrs}

@app.get("/api/filieres/{ufr_id}")
async def get_filieres_api(ufr_id: str, db: Session = Depends(get_db)):
    """Get filières for a specific UFR"""
    filieres = get_filieres_by_ufr(db, ufr_id)
    return {"filieres": filieres}

@app.get("/api/matieres/{filiere_id}")
async def get_matieres_api(filiere_id: str, db: Session = Depends(get_db)):
    """Get matières for a specific filière"""
    matieres = get_matieres_by_filiere(db, filiere_id)
    return {"matieres": matieres}

# APIs pour l'administration - récupérer toutes les données
@app.get("/api/universites")
async def get_all_universites_api(db: Session = Depends(get_db)):
    """Get all universities"""
    universites = db.query(UniversiteDB).all()
    return [
        {
            "id": uni.id,
            "nom": uni.nom,
            "code": uni.code,
            "logo_url": uni.logo_url
        } for uni in universites
    ]

@app.get("/api/all-ufrs")
async def get_all_ufrs_api(db: Session = Depends(get_db)):
    """Get all UFRs with university info"""
    ufrs = db.query(UFRDB).join(UniversiteDB).all()
    return [
        {
            "id": ufr.id,
            "nom": ufr.nom,
            "code": ufr.code,
            "universite_id": ufr.universite_id,
            "universite_nom": ufr.universite.nom
        } for ufr in ufrs
    ]

@app.get("/api/all-filieres")
async def get_all_filieres_api(db: Session = Depends(get_db)):
    """Get all filières with UFR and university info"""
    filieres = db.query(FiliereDB).join(UFRDB).join(UniversiteDB).all()
    return [
        {
            "id": filiere.id,
            "nom": filiere.nom,
            "code": filiere.code,
            "ufr_id": filiere.ufr_id,
            "ufr_nom": filiere.ufr.nom,
            "universite_nom": filiere.ufr.universite.nom
        } for filiere in filieres
    ]

@app.get("/api/all-matieres")
async def get_all_matieres_api(db: Session = Depends(get_db)):
    """Get all matières with filière, UFR and university info"""
    matieres = db.query(MatiereDB).join(FiliereDB).join(UFRDB).join(UniversiteDB).all()
    return [
        {
            "id": matiere.id,
            "nom": matiere.nom,
            "code": matiere.code,
            "filiere_id": matiere.filiere_id,
            "filiere_nom": matiere.filiere.nom,
            "ufr_nom": matiere.filiere.ufr.nom,
            "universite_nom": matiere.filiere.ufr.universite.nom
        } for matiere in matieres
    ]

@app.get("/api/universite/{universite_id}")
async def get_universite_api(universite_id: str, db: Session = Depends(get_db)):
    """Get university information including logo"""
    uni = db.query(UniversiteDB).filter_by(id=universite_id).first()
    
    if uni:
        return {
            "id": uni.id,
            "nom": uni.nom,
            "code": uni.code,
            "logo_url": uni.logo_url
        }
    
    raise HTTPException(status_code=404, detail="Université non trouvée")

# === ROUTES API - COMMENTAIRES (INTERACTION) ===

@app.get("/api/commentaires/{chapitre_id}")
async def get_commentaires(chapitre_id: int, db: Session = Depends(get_db)):
    """Récupérer tous les commentaires d'un chapitre"""
    commentaires = db.query(CommentaireDB).filter_by(chapitre_id=chapitre_id).order_by(CommentaireDB.created_at.desc()).all()
    return [{
        "id": c.id,
        "texte": c.texte,
        "auteur_type": c.auteur_type,
        "auteur_nom": c.auteur_nom,
        "created_at": c.created_at.isoformat()
    } for c in commentaires]

@app.post("/api/commentaires")
async def add_commentaire(
    request: Request,
    commentaire_data: CommentaireCreate,
    db: Session = Depends(get_db)
):
    """Ajouter un commentaire sur un chapitre"""
    role, username, user_data = require_auth(request, db)
    
    # Déterminer l'auteur selon le rôle
    if role == "prof":
        auteur_type = "prof"
        auteur_nom = f"{user_data.get('prenom', '')} {user_data.get('nom', '')}"
        auteur_id = user_data.get('id')
    elif role == "etudiant":
        auteur_type = "etudiant"
        auteur_nom = f"{user_data.get('prenom', '')} {user_data.get('nom', '')}"
        auteur_id = user_data.get('id')
    else:
        raise HTTPException(status_code=403, detail="Seuls les professeurs et étudiants peuvent commenter")
    
    # Créer le commentaire
    nouveau_commentaire = CommentaireDB(
        texte=commentaire_data.texte,
        chapitre_id=commentaire_data.chapitre_id,
        auteur_type=auteur_type,
        auteur_id=auteur_id,
        auteur_nom=auteur_nom
    )
    
    db.add(nouveau_commentaire)
    db.commit()
    db.refresh(nouveau_commentaire)
    
    return {
        "success": True,
        "commentaire": {
            "id": nouveau_commentaire.id,
            "texte": nouveau_commentaire.texte,
            "auteur_type": nouveau_commentaire.auteur_type,
            "auteur_nom": nouveau_commentaire.auteur_nom,
            "created_at": nouveau_commentaire.created_at.isoformat()
        }
    }

@app.delete("/api/commentaires/{commentaire_id}")
async def delete_commentaire(
    request: Request,
    commentaire_id: int,
    db: Session = Depends(get_db)
):
    """Supprimer un commentaire (seulement l'auteur ou un admin)"""
    role, username, user_data = require_auth(request, db)
    
    commentaire = db.query(CommentaireDB).filter_by(id=commentaire_id).first()
    if not commentaire:
        raise HTTPException(status_code=404, detail="Commentaire non trouvé")
    
    # Vérifier les permissions
    if role == "admin":
        # Les admins peuvent supprimer n'importe quel commentaire
        db.delete(commentaire)
        db.commit()
        return {"success": True, "message": "Commentaire supprimé"}
    elif (commentaire.auteur_type == role and commentaire.auteur_id == user_data.get('id')):
        # L'auteur peut supprimer son propre commentaire
        db.delete(commentaire)
        db.commit()
        return {"success": True, "message": "Commentaire supprimé"}
    else:
        raise HTTPException(status_code=403, detail="Vous ne pouvez pas supprimer ce commentaire")

if __name__ == "__main__":
    print("=" * 50)
    print("🎓 Étude LINE - Application Éducative")
    print("=" * 50)
    print(f"🌐 Application démarrée sur: http://0.0.0.0:5000")
    print("💰 Accès gratuit pour tous les étudiants")
    print(f"🔗 Webhook Wave URL: http://0.0.0.0:5000/webhook/wave")
    
    print("🎓 Système de paiement supprimé - accès libre")
    
    print("=" * 50)
    
    uvicorn.run(app, host="0.0.0.0", port=5000, reload=True)
