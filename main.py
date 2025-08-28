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
from sqlalchemy import and_, or_
import uvicorn

# Import database and models
from database import get_db, create_tables
from models import (
    Universite as UniversiteDB, UFR as UFRDB, Filiere as FiliereDB, Matiere as MatiereDB,
    Administrateur as AdministrateurDB, Professeur as ProfesseurDB, Etudiant as EtudiantDB, 
    Content, ChapitreComplet as ChapitreCompletDB
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
        migrate_data()
        print("✅ Migration des données effectuée avec succès")
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

class ChapitreComplet(BaseModel):
    id: str
    universite_id: str
    ufr_id: str
    filiere_id: str
    matiere_id: str
    niveau: str
    semestre: str
    chapitre: str
    titre: str
    # Cours
    cours_texte: Optional[str] = None
    cours_fichier_nom: Optional[str] = None
    cours_fichier_path: Optional[str] = None
    # Exercices
    exercice_texte: Optional[str] = None
    exercice_fichier_nom: Optional[str] = None
    exercice_fichier_path: Optional[str] = None
    # Solutions
    solution_texte: Optional[str] = None
    solution_fichier_nom: Optional[str] = None
    solution_fichier_path: Optional[str] = None
    created_by: str


class Universite(BaseModel):
    id: str
    nom: str
    code: str

class UFR(BaseModel):
    id: str
    nom: str
    code: str
    universite_id: str

class Filiere(BaseModel):
    id: str
    nom: str
    code: str
    ufr_id: str

class Matiere(BaseModel):
    id: str
    nom: str
    code: str
    filiere_id: str

# Utility functions
def now_utc() -> datetime:
    return datetime.utcnow()

def add_days(dt: datetime, days: int) -> datetime:
    return dt + timedelta(days=days)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

# Database helper functions (PostgreSQL)
def create_default_admin_if_needed(db: Session) -> None:
    """Create default admin if none exists"""
    existing_admin = db.query(AdministrateurDB).filter_by(username="admin").first()
    if not existing_admin:
        default_admin = AdministrateurDB(
            username="admin",
            password_hash=hash_password("admin123"),
            nom="AdministrateurDB",
            prenom="Principal",
            is_main_admin=True
        )
        db.add(default_admin)
        db.commit()

def authenticate_user(db: Session, username: str, password: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """Authenticate user against PostgreSQL database"""
    # Try admin first
    admin = db.query(AdministrateurDB).filter_by(username=username).first()
    if admin and verify_password(password, admin.password_hash):
        return "admin", {
            "id": admin.id,
            "username": admin.username,
            "nom": admin.nom,
            "prenom": admin.prenom,
            "is_main_admin": admin.is_main_admin
        }
    
    # Try professor
    prof = db.query(ProfesseurDB).filter_by(username=username).first()
    if prof and verify_password(password, prof.password_hash):
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
                "is_main_admin": admin.is_main_admin
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
    user = get_current_user(request)
    if user:
        role, username = user
        if role == "prof":
            return RedirectResponse(url="/dashboard/prof", status_code=302)
        elif role == "admin":
            return RedirectResponse(url="/dashboard/admin", status_code=302)
        else:
            return RedirectResponse(url="/dashboard/etudiant", status_code=302)
    
    # Load academic data for form
    universites = get_universites(db)
    
    return templates.TemplateResponse("index.html", {
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
    response = RedirectResponse(url="/dashboard/prof", status_code=302)
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
    
    # Create session and redirect
    session_token = create_session_token(username, "etudiant")
    response = RedirectResponse(url="/dashboard/etudiant", status_code=302)
    response.set_cookie("session", session_token, httponly=True)
    
    return response

@app.get("/login", response_class=HTMLResponse)
async def login_form(request: Request):
    """Login form"""
    user = get_current_user(request)
    if user:
        role, username = user
        if role == "prof":
            return RedirectResponse(url="/dashboard/prof", status_code=302)
        elif role == "admin":
            return RedirectResponse(url="/dashboard/admin", status_code=302)
        else:
            return RedirectResponse(url="/dashboard/etudiant", status_code=302)
    
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
    
    response = RedirectResponse(url=redirect_url, status_code=302)
    response.set_cookie("session", session_token, httponly=True)
    
    return response

@app.get("/logout")
async def logout():
    """Logout user"""
    response = RedirectResponse(url="/", status_code=302)
    response.delete_cookie("session")
    return response

@app.get("/dashboard/prof", response_class=HTMLResponse)
async def dashboard_prof(request: Request, db: Session = Depends(get_db)):
    """Professor dashboard"""
    prof_username, user_data = require_prof(request, db)
    
    # Get professor's contents
    prof_contents = db.query(Content).filter(Content.created_by == prof_username).all()
    
    # Get academic structure data first (needed for sorting)
    universites = db.query(UniversiteDB).all()
    ufrs = db.query(UFRDB).all()
    filieres = db.query(FiliereDB).all()
    matieres = db.query(MatiereDB).all()

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
    
    prof = db.query(ProfesseurDB).filter(ProfesseurDB.username == prof_username).first()
    
    return templates.TemplateResponse("dashboard_prof.html", {
        "request": request,
        "prof": prof,
        "contents": prof_contents,
        "chapitres": prof_chapitres,
        "universites": universites,
        "ufrs": ufrs,
        "filieres": filieres,
        "matieres": matieres
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
    prof_username: str = Depends(require_prof),
    db: Session = Depends(get_db)
):
    """Create new content"""
    
    # Validate semester (only S1 and S2 allowed)
    if semestre not in ["S1", "S2"]:
        return RedirectResponse(url="/dashboard/prof?error=Semestre non valide (seuls S1 et S2 sont autorisés)", status_code=302)
    
    # Validate academic level
    if niveau not in ["L1", "L2", "L3", "M1", "M2"]:
        return RedirectResponse(url="/dashboard/prof?error=Niveau d'étude non valide", status_code=302)
    
    # Check if at least one content (text or file) is provided
    if not texte.strip() and not fichier:
        return RedirectResponse(url="/dashboard/prof?error=Veuillez fournir soit du contenu textuel, soit un fichier", status_code=302)
    
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
            return RedirectResponse(url=f"/dashboard/prof?error=Erreur lors de l'upload du fichier: {str(e)}", status_code=302)
    
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
        
        return RedirectResponse(url="/dashboard/prof?success=Contenu publié avec succès", status_code=302)
        
    except Exception as e:
        db.rollback()
        return RedirectResponse(url=f"/dashboard/prof?error=Erreur lors de la création du contenu: {str(e)}", status_code=302)

@app.post("/prof/chapitre-complet")
async def create_chapitre_complet(
    request: Request,
    prof_username: str = Depends(require_prof),
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
    cours_fichier: Optional[UploadFile] = File(None),
    # Exercices
    exercice_texte: str = Form(""),
    exercice_fichier: Optional[UploadFile] = File(None),
    # Solutions
    solution_texte: str = Form(""),
    solution_fichier: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db)
):
    """Create a complete chapter with cours, exercice and solution"""
    # Validate semester (only S1 and S2 allowed)
    if semestre not in ["S1", "S2"]:
        return RedirectResponse(url="/dashboard/prof?error=Semestre non valide (seuls S1 et S2 sont autorisés)", status_code=302)
    
    # Validate academic level
    if niveau not in ["L1", "L2", "L3", "M1", "M2"]:
        return RedirectResponse(url="/dashboard/prof?error=Niveau d'étude non valide", status_code=302)
    
    # Validate that each section has at least text or file
    errors = []
    if not cours_texte.strip() and (not cours_fichier or not cours_fichier.filename):
        errors.append("Cours: vous devez fournir soit du texte soit un fichier")
    
    if not exercice_texte.strip() and (not exercice_fichier or not exercice_fichier.filename):
        errors.append("Exercices: vous devez fournir soit du texte soit un fichier")
        
    if not solution_texte.strip() and (not solution_fichier or not solution_fichier.filename):
        errors.append("Solutions: vous devez fournir soit du texte soit un fichier")
    
    if errors:
        error_msg = " | ".join(errors)
        return RedirectResponse(url=f"/dashboard/prof?error={error_msg}", status_code=302)
    
    # Check if chapter already exists for this context in PostgreSQL
    existing = db.query(ChapitreCompletDB).filter_by(
        filiere_id=filiere_id,
        matiere_id=matiere_id,
        niveau=niveau,
        semestre=semestre,
        chapitre=chapitre
    ).first()
    
    if existing:
        return RedirectResponse(url="/dashboard/prof?error=Ce chapitre existe déjà pour ce niveau/semestre/matière", status_code=302)

    # Helper function to save file
    async def save_file(file: UploadFile, type_folder: str) -> tuple[str, str]:
        if not file or not file.filename:
            return None, None
        
        upload_dir = Path("uploads") / type_folder
        upload_dir.mkdir(parents=True, exist_ok=True)
        
        file_extension = Path(file.filename).suffix
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        file_path = upload_dir / unique_filename
        
        try:
            content = await file.read()
            with open(file_path, "wb") as f:
                f.write(content)
            return file.filename, str(file_path)
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"Erreur upload {type_folder}: {str(e)}")
    
    try:
        # Save files
        cours_nom, cours_path = await save_file(cours_fichier, "cours")
        exercice_nom, exercice_path = await save_file(exercice_fichier, "exercices")
        solution_nom, solution_path = await save_file(solution_fichier, "solutions")
        
        # Create complete chapter in PostgreSQL
        nouveau_chapitre = ChapitreCompletDB(
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
        
        return RedirectResponse(url="/dashboard/prof?success=Chapitre complet créé avec succès", status_code=302)
        
    except Exception as e:
        db.rollback()
        return RedirectResponse(url=f"/dashboard/prof?error=Erreur lors de la création du chapitre: {str(e)}", status_code=302)

@app.get("/uploads/{file_path:path}")
async def serve_uploaded_file(file_path: str):
    """Serve uploaded files with proper content type for browser viewing"""
    import mimetypes
    
    file_location = Path("uploads") / file_path
    
    if not file_location.exists():
        raise HTTPException(status_code=404, detail="Fichier non trouvé")
    
    # Detect MIME type for proper browser handling
    mime_type, _ = mimetypes.guess_type(str(file_location))
    if mime_type is None:
        mime_type = 'application/octet-stream'
    
    return FileResponse(
        path=file_location,
        filename=file_location.name,
        media_type=mime_type
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
                "matiere_id": chapitre.matiere_id,
                "filiere_id": chapitre.filiere_id,
                "created_by": chapitre.created_by
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
        "matieres": matieres
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
async def get_admin_stats(request: Request, db: Session = Depends(get_db)):
    """Get system statistics (admin only)"""
    # Verify admin authentication
    role, username, user_data = require_auth(request, db)
    if role != "admin":
        raise HTTPException(status_code=403, detail="Admin access required")
    
    # Count users
    prof_count = db.query(ProfesseurDB).count()
    student_count = db.query(EtudiantDB).count()
    admin_count = db.query(AdministrateurDB).count()
    
    # Count content by type (from Content table)
    content_stats = {}
    contents = db.query(Content).all()
    for content in contents:
        content_type = content.type
        content_stats[content_type] = content_stats.get(content_type, 0) + 1
    
    # Count chapitres complets by type (cours, exercice, solution)
    chapitres = db.query(ChapitreCompletDB).all()
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
    
    # Academic structure counts
    uni_count = db.query(UniversiteDB).count()
    ufr_count = db.query(UFRDB).count()
    filiere_count = db.query(FiliereDB).count()
    matiere_count = db.query(MatiereDB).count()
    
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
    
    # Get all administrators
    admins = db.query(AdministrateurDB).all()
    admins_data = [{
        "id": admin.id,
        "username": admin.username,
        "nom": admin.nom,
        "prenom": admin.prenom,
        "is_main_admin": admin.is_main_admin
    } for admin in admins]
    
    # Get all professors  
    profs = db.query(ProfesseurDB).all()
    profs_data = [{
        "id": prof.id,
        "username": prof.username,
        "nom": prof.nom,
        "prenom": prof.prenom,
        "specialite": prof.specialite,
        "matiere": prof.matiere
    } for prof in profs]
    
    # Get academic structure data
    universites = get_universites(db)
    ufrs_data = db.query(UFRDB).all()
    filieres_data = db.query(FiliereDB).all()
    matieres_data = db.query(MatiereDB).all()
    
    # Get statistics for display
    stats_response = await get_admin_stats(request, db)
    
    return templates.TemplateResponse("dashboard_admin.html", {
        "request": request,
        "admin": admin_user,
        "admins": admins_data,
        "profs": profs_data,
        "universites": universites,
        "ufrs": ufrs_data,
        "filieres": filieres_data,
        "matieres": matieres_data,
        "stats": stats_response
    })

@app.post("/admin/create-admin")
async def admin_create_admin(
    request: Request,
    nom: str = Form(...),
    prenom: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
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
        
        # Créer le nouvel administrateur
        new_admin = AdministrateurDB(
            username=username,
            password_hash=pwd_context.hash(password),
            nom=nom,
            prenom=prenom,
            is_main_admin=False
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
            return RedirectResponse(url="/dashboard/admin?error=Ce nom d'utilisateur existe déjà", status_code=302)
        
        # Validate hierarchical relationships
        universite = db.query(UniversiteDB).filter(UniversiteDB.id == universite_id).first()
        if not universite:
            return RedirectResponse(url="/dashboard/admin?error=Université non trouvée", status_code=302)
        
        ufr = db.query(UFRDB).filter(UFRDB.id == ufr_id, UFRDB.universite_id == universite_id).first()
        if not ufr:
            return RedirectResponse(url="/dashboard/admin?error=UFR non valide pour cette université", status_code=302)
        
        filiere = db.query(FiliereDB).filter(FiliereDB.id == filiere_id, FiliereDB.ufr_id == ufr_id).first()
        if not filiere:
            return RedirectResponse(url="/dashboard/admin?error=Filière non valide pour cette UFR", status_code=302)
        
        matiere = db.query(MatiereDB).filter(MatiereDB.id == matiere_id, MatiereDB.filiere_id == filiere_id).first()
        if not matiere:
            return RedirectResponse(url="/dashboard/admin?error=Matière non valide pour cette filière", status_code=302)
        
        # Create new professor with hierarchical structure
        new_prof = ProfesseurDB(
            username=username,
            password_hash=pwd_context.hash(password),
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
        return RedirectResponse(url="/dashboard/admin?success=Professeur créé avec succès", status_code=302)
        
    except Exception as e:
        db.rollback()
        return RedirectResponse(url=f"/dashboard/admin?error=Erreur lors de la création: {str(e)}", status_code=302)

@app.post("/admin/create-universite")
async def admin_create_universite(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    nom: str = Form(...),
    code: str = Form(...),
    db: Session = Depends(get_db)
):
    """Admin creates new university"""
    admin_username, admin_data = admin_info
    
    try:
        # Check if code already exists
        existing_universite = db.query(UniversiteDB).filter(UniversiteDB.code == code).first()
        if existing_universite:
            return RedirectResponse(url="/dashboard/admin?error=Code université déjà existant", status_code=302)
        
        # Create new university
        new_universite = UniversiteDB(
            id=str(uuid.uuid4()),
            nom=nom,
            code=code,
            logo_url=None
        )
        
        db.add(new_universite)
        db.commit()
        return RedirectResponse(url="/dashboard/admin?success=Université créée avec succès", status_code=302)
        
    except Exception as e:
        db.rollback()
        return RedirectResponse(url=f"/dashboard/admin?error=Erreur lors de la création: {str(e)}", status_code=302)

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
    
    try:
        # Check if university exists
        universite = db_session.query(UniversiteDB).filter(UniversiteDB.id == universite_id).first()
        if not universite:
            return RedirectResponse(url="/dashboard/admin?error=Université non trouvée", status_code=302)
        
        # Check if code already exists for this university
        existing_ufr = db_session.query(UFRDB).filter(
            UFRDB.code == code, 
            UFRDB.universite_id == universite_id
        ).first()
        if existing_ufr:
            return RedirectResponse(url="/dashboard/admin?error=Code UFR déjà existant pour cette université", status_code=302)
        
        # Create new UFR
        new_ufr = UFRDB(
            id=str(uuid.uuid4()),
            nom=nom,
            code=code,
            universite_id=universite_id
        )
        
        db_session.add(new_ufr)
        db_session.commit()
        return RedirectResponse(url="/dashboard/admin?success=UFR créée avec succès", status_code=302)
        
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(url=f"/dashboard/admin?error=Erreur lors de la création: {str(e)}", status_code=302)
    finally:
        db_session.close()

@app.post("/admin/create-filiere")
async def admin_create_filiere(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    nom: str = Form(...),
    code: str = Form(...),
    ufr_id: str = Form(...)
):
    """Admin creates new filière"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    try:
        # Check if UFR exists
        ufr = db_session.query(UFRDB).filter(UFRDB.id == ufr_id).first()
        if not ufr:
            return RedirectResponse(url="/dashboard/admin?error=UFR non trouvée", status_code=302)
        
        # Check if code already exists for this UFR
        existing_filiere = db_session.query(FiliereDB).filter(
            FiliereDB.code == code, 
            FiliereDB.ufr_id == ufr_id
        ).first()
        if existing_filiere:
            return RedirectResponse(url="/dashboard/admin?error=Code filière déjà existant pour cette UFR", status_code=302)
        
        # Create new filiere
        new_filiere = FiliereDB(
            id=str(uuid.uuid4()),
            nom=nom,
            code=code,
            ufr_id=ufr_id
        )
        
        db_session.add(new_filiere)
        db_session.commit()
        return RedirectResponse(url="/dashboard/admin?success=Filière créée avec succès", status_code=302)
        
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(url=f"/dashboard/admin?error=Erreur lors de la création: {str(e)}", status_code=302)
    finally:
        db_session.close()

@app.post("/admin/create-matiere")
async def admin_create_matiere(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    nom: str = Form(...),
    code: str = Form(...),
    filiere_id: str = Form(...)
):
    """Admin creates new matière"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    try:
        # Check if filiere exists
        filiere = db_session.query(FiliereDB).filter(FiliereDB.id == filiere_id).first()
        if not filiere:
            return RedirectResponse(url="/dashboard/admin?error=Filière non trouvée", status_code=302)
        
        # Check if code already exists for this filiere
        existing_matiere = db_session.query(MatiereDB).filter(
            MatiereDB.code == code, 
            MatiereDB.filiere_id == filiere_id
        ).first()
        if existing_matiere:
            return RedirectResponse(url="/dashboard/admin?error=Code matière déjà existant pour cette filière", status_code=302)
        
        # Create new matiere
        new_matiere = MatiereDB(
            id=str(uuid.uuid4()),
            nom=nom,
            code=code,
            filiere_id=filiere_id
        )
        
        db_session.add(new_matiere)
        db_session.commit()
        return RedirectResponse(url="/dashboard/admin?success=Matière créée avec succès", status_code=302)
        
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(url=f"/dashboard/admin?error=Erreur lors de la création: {str(e)}", status_code=302)
    finally:
        db_session.close()

# Routes pour modification et suppression

# Admin routes
@app.post("/admin/edit-admin")
async def admin_edit_admin(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    username: str = Form(...),
    nom: str = Form(...),
    prenom: str = Form(...)
):
    """Edit administrator (only for principal admin)"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    # Vérifier que seul l'admin principal peut modifier des admins
    if not admin_data.get("is_main_admin", False):
        return RedirectResponse("/dashboard/admin?error=Seul l'administrateur principal peut modifier des administrateurs", status_code=303)
    
    try:
        admin = db_session.query(AdministrateurDB).filter(AdministrateurDB.username == username).first()
        if admin:
            admin.nom = nom
            admin.prenom = prenom
            db_session.commit()
            return RedirectResponse("/dashboard/admin?success=Administrateur modifié avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Administrateur non trouvé", status_code=303)
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la modification: {str(e)}", status_code=303)
    finally:
        db_session.close()

@app.post("/admin/delete-admin")
async def admin_delete_admin(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    username: str = Form(...)
):
    """Delete administrator (only for principal admin)"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    # Vérifier que seul l'admin principal peut supprimer des admins
    if not admin_data.get("is_main_admin", False):
        return RedirectResponse("/dashboard/admin?error=Seul l'administrateur principal peut supprimer des administrateurs", status_code=303)
    
    # L'admin principal ne peut pas être supprimé
    if username == "maodoka65":
        return RedirectResponse("/dashboard/admin?error=L'administrateur principal ne peut pas être supprimé", status_code=303)
    
    try:
        admin = db_session.query(AdministrateurDB).filter(AdministrateurDB.username == username).first()
        if admin:
            db_session.delete(admin)
            db_session.commit()
            return RedirectResponse("/dashboard/admin?success=Administrateur supprimé avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Administrateur non trouvé", status_code=303)
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)
    finally:
        db_session.close()

# Professor routes
@app.post("/admin/edit-prof")
async def admin_edit_prof(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    username: str = Form(...),
    nom: str = Form(...),
    prenom: str = Form(...),
    specialite: str = Form(...)
):
    """Edit professor"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    try:
        prof = db_session.query(ProfesseurDB).filter(ProfesseurDB.username == username).first()
        if prof:
            prof.nom = nom
            prof.prenom = prenom
            prof.specialite = specialite
            db_session.commit()
            return RedirectResponse("/dashboard/admin?success=Professeur modifié avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Professeur non trouvé", status_code=303)
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la modification: {str(e)}", status_code=303)
    finally:
        db_session.close()

@app.post("/admin/delete-prof")
async def admin_delete_prof(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    username: str = Form(...)
):
    """Delete professor and all their content"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    try:
        prof = db_session.query(ProfesseurDB).filter(ProfesseurDB.username == username).first()
        if prof:
            # Supprimer d'abord tout le contenu créé par ce professeur
            chapitres = db_session.query(ChapitreComplet).filter(ChapitreComplet.created_by == username).all()
            for chapitre in chapitres:
                db_session.delete(chapitre)
            
            # Puis supprimer le professeur
            db_session.delete(prof)
            db_session.commit()
            return RedirectResponse("/dashboard/admin?success=Professeur et son contenu supprimés avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Professeur non trouvé", status_code=303)
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)
    finally:
        db_session.close()

# University routes
@app.post("/admin/edit-universite")
async def admin_edit_universite(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...),
    nom: str = Form(...),
    code: str = Form(...)
):
    """Edit university"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    try:
        universite = db_session.query(UniversiteDB).filter(UniversiteDB.id == id).first()
        if universite:
            universite.nom = nom
            universite.code = code
            db_session.commit()
            return RedirectResponse("/dashboard/admin?success=Université modifiée avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Université non trouvée", status_code=303)
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la modification: {str(e)}", status_code=303)
    finally:
        db_session.close()

@app.post("/admin/delete-universite")
async def admin_delete_universite(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...)
):
    """Delete university and all related data"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    try:
        universite = db_session.query(UniversiteDB).filter(UniversiteDB.id == id).first()
        if universite:
            # Supprimer en cascade (PostgreSQL s'occupera des relations)
            db_session.delete(universite)
            db_session.commit()
            return RedirectResponse("/dashboard/admin?success=Université et toutes ses données supprimées avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Université non trouvée", status_code=303)
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)
    finally:
        db_session.close()

# UFR routes
@app.post("/admin/edit-ufr")
async def admin_edit_ufr(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...),
    nom: str = Form(...),
    code: str = Form(...)
):
    """Edit UFR"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    try:
        ufr = db_session.query(UFRDB).filter(UFRDB.id == id).first()
        if ufr:
            ufr.nom = nom
            ufr.code = code
            db_session.commit()
            return RedirectResponse("/dashboard/admin?success=UFR modifiée avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=UFR non trouvée", status_code=303)
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la modification: {str(e)}", status_code=303)
    finally:
        db_session.close()

@app.post("/admin/delete-ufr")
async def admin_delete_ufr(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...)
):
    """Delete UFR and all related data"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    try:
        ufr = db_session.query(UFRDB).filter(UFRDB.id == id).first()
        if ufr:
            # PostgreSQL s'occupera des suppressions en cascade
            db_session.delete(ufr)
            db_session.commit()
            return RedirectResponse("/dashboard/admin?success=UFR et toutes ses données supprimées avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=UFR non trouvée", status_code=303)
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)
    finally:
        db_session.close()

# Filière routes
@app.post("/admin/edit-filiere")
async def admin_edit_filiere(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...),
    nom: str = Form(...),
    code: str = Form(...)
):
    """Edit filière"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    try:
        filiere = db_session.query(FiliereDB).filter(FiliereDB.id == id).first()
        if filiere:
            filiere.nom = nom
            filiere.code = code
            db_session.commit()
            return RedirectResponse("/dashboard/admin?success=Filière modifiée avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Filière non trouvée", status_code=303)
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la modification: {str(e)}", status_code=303)
    finally:
        db_session.close()

@app.post("/admin/delete-filiere")
async def admin_delete_filiere(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...)
):
    """Delete filière and all related data"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    try:
        filiere = db_session.query(FiliereDB).filter(FiliereDB.id == id).first()
        if filiere:
            # PostgreSQL s'occupera des suppressions en cascade
            db_session.delete(filiere)
            db_session.commit()
            return RedirectResponse("/dashboard/admin?success=Filière et toutes ses données supprimées avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Filière non trouvée", status_code=303)
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)
    finally:
        db_session.close()

# Matière routes
@app.post("/admin/edit-matiere")
async def admin_edit_matiere(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...),
    nom: str = Form(...),
    code: str = Form(...)
):
    """Edit matière"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    try:
        matiere = db_session.query(MatiereDB).filter(MatiereDB.id == id).first()
        if matiere:
            matiere.nom = nom
            matiere.code = code
            db_session.commit()
            return RedirectResponse("/dashboard/admin?success=Matière modifiée avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Matière non trouvée", status_code=303)
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la modification: {str(e)}", status_code=303)
    finally:
        db_session.close()

@app.post("/admin/delete-matiere")
async def admin_delete_matiere(
    request: Request,
    admin_info: Tuple[str, Dict[str, Any]] = Depends(require_admin),
    id: str = Form(...)
):
    """Delete matière and all related content"""
    db_session = next(get_db())
    admin_username, admin_data = admin_info
    
    try:
        matiere = db_session.query(MatiereDB).filter(MatiereDB.id == id).first()
        if matiere:
            # PostgreSQL s'occupera des suppressions en cascade
            db_session.delete(matiere)
            db_session.commit()
            return RedirectResponse("/dashboard/admin?success=Matière et son contenu supprimés avec succès", status_code=303)
        else:
            return RedirectResponse("/dashboard/admin?error=Matière non trouvée", status_code=303)
    except Exception as e:
        db_session.rollback()
        return RedirectResponse(f"/dashboard/admin?error=Erreur lors de la suppression: {str(e)}", status_code=303)
    finally:
        db_session.close()

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
    prof_username: str = Depends(require_prof),
    chapitre_id: str = Form(...),
    db: Session = Depends(get_db)
):
    """Professor deletes their chapter"""
    try:
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

# API endpoints for hierarchical data
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
