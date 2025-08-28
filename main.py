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
from pydantic import BaseModel, validator
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer
import uvicorn

# Initialize FastAPI app
app = FastAPI(title="Étude LINE", description="Application éducative")
templates = Jinja2Templates(directory="templates")

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

class UserEtudiant(BaseModel):
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

# Database functions with file locking
def load_db() -> Dict[str, Any]:
    """Load database with file locking"""
    db_path = Path("data.json")
    
    if not db_path.exists():
        # Initialize empty database
        initial_db = {
            "users": {"prof": [], "etudiant": [], "admin": []},
            "contents": [],
            "chapitres_complets": [],
            "universites": [],
            "ufrs": [],
            "filieres": [],
            "matieres": []
        }
        save_db(initial_db)
        create_default_admin(initial_db)
        return initial_db
    
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # Shared lock for reading
            data = json.load(f)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)  # Unlock
        create_default_admin(data)
        return data
    except (json.JSONDecodeError, FileNotFoundError):
        # Return empty structure if file is corrupted
        return {
            "users": {"prof": [], "etudiant": [], "admin": []},
            "contents": [],
            "chapitres_complets": [],
            "universites": [],
            "ufrs": [],
            "filieres": [],
            "matieres": []
        }

def save_db(db: Dict[str, Any]) -> None:
    """Save database with file locking"""
    db_path = Path("data.json")
    
    # Convert datetime objects to strings for JSON serialization
    def serialize_datetime(obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        raise TypeError(f"Object of type {type(obj)} is not JSON serializable")
    
    with open(db_path, "w", encoding="utf-8") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)  # Exclusive lock for writing
        json.dump(db, f, ensure_ascii=False, indent=2, default=serialize_datetime)
        fcntl.flock(f.fileno(), fcntl.LOCK_UN)  # Unlock

def create_default_admin(db: Dict[str, Any]) -> None:
    """Create default admin if none exists"""
    if not db["users"]["admin"]:
        default_admin = {
            "username": "admin",
            "password_hash": hash_password("admin123"),
            "nom": "Administrateur",
            "prenom": "Principal"
        }
        db["users"]["admin"].append(default_admin)
        save_db(db)

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

def require_auth(request: Request) -> Tuple[str, str]:
    """Dependency to require authentication"""
    user = get_current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required"
        )
    return user

def require_prof(request: Request) -> str:
    """Dependency to require professor role"""
    role, username = require_auth(request)
    if role != "prof":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Professor access required"
        )
    return username

def require_etudiant(request: Request) -> str:
    """Dependency to require student role"""
    role, username = require_auth(request)
    if role != "etudiant":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Student access required"
        )
    return username

def require_admin(request: Request) -> str:
    """Dependency to require admin role"""
    role, username = require_auth(request)
    if role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Administrator access required"
        )
    return username

# Helper functions
def find_user(username: str, role: str) -> Optional[Dict[str, Any]]:
    """Find user by username and role"""
    db = load_db()
    users = db["users"][role]
    for user in users:
        if user["username"] == username:
            return user
    return None

def get_student_profile(username: str) -> Optional[Dict[str, str]]:
    """Get student profile with backward compatibility"""
    user = find_user(username, "etudiant")
    if user:
        # Handle both old and new data formats
        if "universite_id" in user:  # New format
            return {
                "username": user["username"],
                "nom": user["nom"],
                "prenom": user["prenom"],
                "universite_id": user["universite_id"],
                "ufr_id": user["ufr_id"],
                "filiere_id": user["filiere_id"],
                "niveau": user["niveau"]
            }
        else:  # Old format
            return {
                "username": user["username"],
                "nom": user["nom"],
                "prenom": user["prenom"],
                "universite": user.get("universite", ""),
                "filiere": user.get("filiere", ""),
                "niveau": user["niveau"]
            }
    return None

def has_content_access(username: str, semestre: str) -> bool:
    """All students have free access to content"""
    return True  # Free access for all students

def get_accessible_content(username: str) -> List[Dict[str, Any]]:
    """Get content accessible to student based on active subscriptions"""
    db = load_db()
    student = get_student_profile(username)
    if not student:
        return []
    
    accessible_content = []
    
    for content in db["contents"]:
        # Handle both old and new content formats
        content_matches = False
        
        if "universite_id" in student and "universite_id" in content:
            # New format comparison
            content_matches = (
                content["universite_id"] == student["universite_id"] and
                content["filiere_id"] == student["filiere_id"] and
                content["niveau"] == student["niveau"]
            )
        elif "universite" in student and "universite" in content:
            # Old format comparison
            content_matches = (
                content["universite"] == student["universite"] and
                content["filiere"] == student["filiere"] and
                content["niveau"] == student["niveau"]
            )
        
        if content_matches:
            # All students have free access to content
            accessible_content.append(content)
    
    return accessible_content

# Helper functions for academic structure
def get_universites(db: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Get all universities"""
    return db.get("universites", [])

def get_ufrs_by_universite(db: Dict[str, Any], universite_id: str) -> List[Dict[str, Any]]:
    """Get UFRs for a specific university"""
    return [ufr for ufr in db.get("ufrs", []) if ufr["universite_id"] == universite_id]

def get_filieres_by_ufr(db: Dict[str, Any], ufr_id: str) -> List[Dict[str, Any]]:
    """Get filières for a specific UFR"""
    return [filiere for filiere in db.get("filieres", []) if filiere["ufr_id"] == ufr_id]

def get_matieres_by_filiere(db: Dict[str, Any], filiere_id: str) -> List[Dict[str, Any]]:
    """Get matières for a specific filière"""
    return [matiere for matiere in db.get("matieres", []) if matiere["filiere_id"] == filiere_id]

# Helper functions to get names from IDs
def get_universite_name(db: Dict[str, Any], universite_id: str) -> str:
    """Get university name from ID"""
    for uni in db.get("universites", []):
        if uni["id"] == universite_id:
            return uni["nom"]
    return "Université inconnue"

def get_ufr_name(db: Dict[str, Any], ufr_id: str) -> str:
    """Get UFR name from ID"""
    for ufr in db.get("ufrs", []):
        if ufr["id"] == ufr_id:
            return ufr["nom"]
    return "UFR inconnue"

def get_filiere_name(db: Dict[str, Any], filiere_id: str) -> str:
    """Get filière name from ID"""
    for filiere in db.get("filieres", []):
        if filiere["id"] == filiere_id:
            return filiere["nom"]
    return "Filière inconnue"

def get_matiere_name(db: Dict[str, Any], matiere_id: str) -> str:
    """Get matière name from ID"""
    for matiere in db.get("matieres", []):
        if matiere["id"] == matiere_id:
            return matiere["nom"]
    return "Matière inconnue"

def migrate_data_to_new_format():
    """Migrate existing data to new hierarchical format"""
    db = load_db()
    migration_needed = False
    
    # Check if we need to migrate students
    for student in db["users"]["etudiant"]:
        if "universite" in student and "universite_id" not in student:
            # Find university by name and add ID
            for uni in db.get("universites", []):
                if uni["nom"].lower() == student["universite"].lower():
                    student["universite_id"] = uni["id"]
                    migration_needed = True
                    break
            
            # Find filiere by name and add ID
            if "filiere" in student:
                for filiere in db.get("filieres", []):
                    if filiere["nom"].lower() == student["filiere"].lower():
                        student["filiere_id"] = filiere["id"]
                        # Also find UFR
                        for ufr in db.get("ufrs", []):
                            if ufr["id"] == filiere["ufr_id"]:
                                student["ufr_id"] = ufr["id"]
                                break
                        migration_needed = True
                        break
    
    # Check if we need to migrate content
    for content in db["contents"]:
        if "universite" in content and "universite_id" not in content:
            # Find university by name
            for uni in db.get("universites", []):
                if uni["nom"].lower() == content["universite"].lower():
                    content["universite_id"] = uni["id"]
                    migration_needed = True
                    break
            
            # Find filiere by name
            if "filiere" in content:
                for filiere in db.get("filieres", []):
                    if filiere["nom"].lower() == content["filiere"].lower():
                        content["filiere_id"] = filiere["id"]
                        # Also find UFR
                        for ufr in db.get("ufrs", []):
                            if ufr["id"] == filiere["ufr_id"]:
                                content["ufr_id"] = ufr["id"]
                                break
                        migration_needed = True
                        break
            
            # Find matiere by name
            if "matiere" in content:
                for matiere in db.get("matieres", []):
                    if matiere["nom"].lower() == content["matiere"].lower():
                        content["matiere_id"] = matiere["id"]
                        migration_needed = True
                        break
    
    if migration_needed:
        save_db(db)
        print("✅ Migration des données effectuée avec succès")
    
    return migration_needed

# Exécuter la migration au démarrage
@app.on_event("startup")
async def startup_event():
    """Run data migration on startup"""
    migrate_data_to_new_format()

# Routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
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
    db = load_db()
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
    matiere: str = Form(...)
):
    """Register new professor"""
    db = load_db()
    
    # Check if username already exists
    if find_user(username, "prof") or find_user(username, "etudiant") or find_user(username, "admin"):
        return templates.TemplateResponse(
            "index.html", 
            {"request": request, "error": "Ce nom d'utilisateur existe déjà"}
        )
    
    # Create new professor
    new_prof = {
        "username": username,
        "password_hash": hash_password(password),
        "nom": nom,
        "prenom": prenom,
        "specialite": specialite,
        "matiere": matiere
    }
    
    db["users"]["prof"].append(new_prof)
    save_db(db)
    
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
    niveau: str = Form(...)
):
    """Register new student"""
    db = load_db()
    
    # Check if username already exists
    if find_user(username, "prof") or find_user(username, "etudiant") or find_user(username, "admin"):
        universites = get_universites(db)
        return templates.TemplateResponse(
            "index.html", 
            {"request": request, "error": "Ce nom d'utilisateur existe déjà", "universites": universites}
        )
    
    # Create new student
    new_etudiant = {
        "username": username,
        "password_hash": hash_password(password),
        "nom": nom,
        "prenom": prenom,
        "universite_id": universite_id,
        "ufr_id": ufr_id,
        "filiere_id": filiere_id,
        "niveau": niveau
    }
    
    db["users"]["etudiant"].append(new_etudiant)
    save_db(db)
    
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
    role: str = Form(...)
):
    """Process login"""
    # Find user in the specified role
    user = find_user(username, role)
    
    if not user or not verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Nom d'utilisateur, mot de passe ou rôle incorrect"}
        )
    
    # Create session and redirect
    session_token = create_session_token(username, role)
    if role == "admin":
        redirect_url = "/dashboard/admin"
    elif role == "prof":
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
async def dashboard_prof(request: Request, prof_username: str = Depends(require_prof)):
    """Professor dashboard"""
    db = load_db()
    
    # Get professor's contents
    prof_contents = [c for c in db["contents"] if c["created_by"] == prof_username]
    
    # Get professor's complete chapters
    prof_chapitres = []
    if "chapitres_complets" in db:
        prof_chapitres = [c for c in db["chapitres_complets"] if c["created_by"] == prof_username]
    
    # Get academic structure data
    universites = get_universites(db)
    ufrs = db.get("ufrs", [])
    filieres = db.get("filieres", [])
    matieres = db.get("matieres", [])
    
    prof = find_user(prof_username, "prof")
    
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
    prof_username: str = Depends(require_prof),
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
    fichier: Optional[UploadFile] = File(None)
):
    """Create new content"""
    db = load_db()
    
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
    
    # Create new content item
    new_content = {
        "id": str(uuid.uuid4()),
        "type": type,
        "universite_id": universite_id,
        "ufr_id": ufr_id,
        "filiere_id": filiere_id,
        "matiere_id": matiere_id,
        "niveau": niveau,
        "semestre": semestre,
        "chapitre": chapitre,
        "titre": titre,
        "texte": texte,
        "fichier_nom": fichier_nom,
        "fichier_path": fichier_path,
        "created_by": prof_username
    }
    
    db["contents"].append(new_content)
    save_db(db)
    
    return RedirectResponse(url="/dashboard/prof?success=Contenu publié avec succès", status_code=302)

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
    solution_fichier: Optional[UploadFile] = File(None)
):
    """Create a complete chapter with cours, exercice and solution"""
    db = load_db()
    
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
    
    # Check if chapter already exists for this context
    existing = None
    if "chapitres_complets" not in db:
        db["chapitres_complets"] = []
    
    for chap in db["chapitres_complets"]:
        if (chap["universite_id"] == universite_id and 
            chap["filiere_id"] == filiere_id and 
            chap["matiere_id"] == matiere_id and 
            chap["niveau"] == niveau and 
            chap["semestre"] == semestre and 
            chap["chapitre"] == chapitre):
            existing = chap
            break
    
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
    
    # Save files
    cours_nom, cours_path = await save_file(cours_fichier, "cours")
    exercice_nom, exercice_path = await save_file(exercice_fichier, "exercices")
    solution_nom, solution_path = await save_file(solution_fichier, "solutions")
    
    # Create complete chapter
    nouveau_chapitre = {
        "id": str(uuid.uuid4()),
        "universite_id": universite_id,
        "ufr_id": ufr_id,
        "filiere_id": filiere_id,
        "matiere_id": matiere_id,
        "niveau": niveau,
        "semestre": semestre,
        "chapitre": chapitre,
        "titre": titre,
        # Cours
        "cours_texte": cours_texte,
        "cours_fichier_nom": cours_nom,
        "cours_fichier_path": cours_path,
        # Exercices
        "exercice_texte": exercice_texte,
        "exercice_fichier_nom": exercice_nom,
        "exercice_fichier_path": exercice_path,
        # Solutions
        "solution_texte": solution_texte,
        "solution_fichier_nom": solution_nom,
        "solution_fichier_path": solution_path,
        "created_by": prof_username
    }
    
    db["chapitres_complets"].append(nouveau_chapitre)
    save_db(db)
    
    return RedirectResponse(url="/dashboard/prof?success=Chapitre complet créé avec succès", status_code=302)

@app.get("/uploads/{file_path:path}")
async def serve_uploaded_file(file_path: str):
    """Serve uploaded files"""
    file_location = Path("uploads") / file_path
    
    if not file_location.exists():
        raise HTTPException(status_code=404, detail="Fichier non trouvé")
    
    return FileResponse(
        path=file_location,
        filename=file_location.name,
        media_type='application/octet-stream'
    )

@app.get("/dashboard/etudiant", response_class=HTMLResponse)
async def dashboard_etudiant(request: Request, etudiant_username: str = Depends(require_etudiant)):
    """Student dashboard"""
    db = load_db()
    student = get_student_profile(etudiant_username)
    
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
    
    # Get accessible content
    accessible_content = get_accessible_content(etudiant_username)
    
    # Get unique subjects and chapters for filtering
    subjects = list(set([c.get("matiere", c.get("matiere_id", "")) for c in accessible_content]))
    chapters = list(set([c["chapitre"] for c in accessible_content]))
    
    # Get academic structure data for display
    universites = get_universites(db)
    ufrs = db.get("ufrs", [])
    filieres = db.get("filieres", [])
    matieres = db.get("matieres", [])
    
    return templates.TemplateResponse("dashboard_etudiant.html", {
        "request": request,
        "student": student,
        "semester_status": semester_status,
        "accessible_content": accessible_content,
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
async def get_admin_stats(admin_username: str = Depends(require_admin)):
    """Get system statistics (admin only)"""
    db = load_db()
    
    # Count users
    prof_count = len(db["users"]["prof"])
    student_count = len(db["users"]["etudiant"])
    
    # Count content by type
    content_stats = {}
    for content in db["contents"]:
        content_type = content["type"]
        content_stats[content_type] = content_stats.get(content_type, 0) + 1
    
    # No subscription system - all content is free
    active_subs = 0
    
    # Academic structure counts
    uni_count = len(db.get("universites", []))
    ufr_count = len(db.get("ufrs", []))
    filiere_count = len(db.get("filieres", []))
    matiere_count = len(db.get("matieres", []))
    
    return {
        "users": {
            "professeurs": prof_count,
            "etudiants": student_count
        },
        "contenu": content_stats,
        "subscriptions_actives": active_subs,
        "structure_academique": {
            "universites": uni_count,
            "ufrs": ufr_count,
            "filieres": filiere_count,
            "matieres": matiere_count
        },
        "total_content": len(db["contents"])
    }


@app.get("/content")
async def get_content(request: Request, etudiant_username: str = Depends(require_etudiant)):
    """Get accessible content for student (API endpoint)"""
    content = get_accessible_content(etudiant_username)
    return {"content": content}

@app.get("/dashboard/admin", response_class=HTMLResponse)
async def dashboard_admin(request: Request, admin_username: str = Depends(require_admin)):
    """Admin dashboard"""
    db = load_db()
    
    # Get all professors
    profs = db["users"]["prof"]
    
    # Get academic structure data
    universites = get_universites(db)
    ufrs = db.get("ufrs", [])
    filieres = db.get("filieres", [])
    matieres = db.get("matieres", [])
    
    admin = find_user(admin_username, "admin")
    
    return templates.TemplateResponse("dashboard_admin.html", {
        "request": request,
        "admin": admin,
        "profs": profs,
        "universites": universites,
        "ufrs": ufrs,
        "filieres": filieres,
        "matieres": matieres
    })

@app.post("/admin/create-prof")
async def admin_create_prof(
    request: Request,
    admin_username: str = Depends(require_admin),
    nom: str = Form(...),
    prenom: str = Form(...),
    username: str = Form(...),
    password: str = Form(...),
    specialite: str = Form(...),
    universite_id: str = Form(...),
    ufr_id: str = Form(...),
    filiere_id: str = Form(...),
    matiere_id: str = Form(...)
):
    """Admin creates new professor with hierarchical structure"""
    db = load_db()
    
    # Check if username already exists
    if find_user(username, "prof") or find_user(username, "etudiant") or find_user(username, "admin"):
        return RedirectResponse(url="/dashboard/admin?error=Ce nom d'utilisateur existe déjà", status_code=302)
    
    # Validate hierarchical relationships
    universite = next((u for u in db.get("universites", []) if u["id"] == universite_id), None)
    if not universite:
        return RedirectResponse(url="/dashboard/admin?error=Université non trouvée", status_code=302)
    
    ufr = next((u for u in db.get("ufrs", []) if u["id"] == ufr_id and u["universite_id"] == universite_id), None)
    if not ufr:
        return RedirectResponse(url="/dashboard/admin?error=UFR non valide pour cette université", status_code=302)
    
    filiere = next((f for f in db.get("filieres", []) if f["id"] == filiere_id and f["ufr_id"] == ufr_id), None)
    if not filiere:
        return RedirectResponse(url="/dashboard/admin?error=Filière non valide pour cette UFR", status_code=302)
    
    matiere = next((m for m in db.get("matieres", []) if m["id"] == matiere_id and m["filiere_id"] == filiere_id), None)
    if not matiere:
        return RedirectResponse(url="/dashboard/admin?error=Matière non valide pour cette filière", status_code=302)
    
    # Create new professor with hierarchical structure
    new_prof = {
        "username": username,
        "password_hash": hash_password(password),
        "nom": nom,
        "prenom": prenom,
        "specialite": specialite,
        "universite_id": universite_id,
        "ufr_id": ufr_id,
        "filiere_id": filiere_id,
        "matiere_id": matiere_id,
        # Keep backward compatibility
        "matiere": matiere["nom"]
    }
    
    db["users"]["prof"].append(new_prof)
    save_db(db)
    
    return RedirectResponse(url="/dashboard/admin?success=Professeur créé avec succès", status_code=302)

@app.post("/admin/create-universite")
async def admin_create_universite(
    request: Request,
    admin_username: str = Depends(require_admin),
    nom: str = Form(...),
    code: str = Form(...)
):
    """Admin creates new university"""
    db = load_db()
    
    # Check if code already exists
    if any(u["code"] == code for u in db.get("universites", [])):
        return RedirectResponse(url="/dashboard/admin?error=Code université déjà existant", status_code=302)
    
    # Create new university
    new_universite = {
        "id": str(uuid.uuid4()),
        "nom": nom,
        "code": code
    }
    
    if "universites" not in db:
        db["universites"] = []
    db["universites"].append(new_universite)
    save_db(db)
    
    return RedirectResponse(url="/dashboard/admin?success=Université créée avec succès", status_code=302)

@app.post("/admin/create-ufr")
async def admin_create_ufr(
    request: Request,
    admin_username: str = Depends(require_admin),
    nom: str = Form(...),
    code: str = Form(...),
    universite_id: str = Form(...)
):
    """Admin creates new UFR"""
    db = load_db()
    
    # Check if code already exists for this university
    existing_ufrs = get_ufrs_by_universite(db, universite_id)
    if any(u["code"] == code for u in existing_ufrs):
        return RedirectResponse(url="/dashboard/admin?error=Code UFR déjà existant pour cette université", status_code=302)
    
    # Create new UFR
    new_ufr = {
        "id": str(uuid.uuid4()),
        "nom": nom,
        "code": code,
        "universite_id": universite_id
    }
    
    if "ufrs" not in db:
        db["ufrs"] = []
    db["ufrs"].append(new_ufr)
    save_db(db)
    
    return RedirectResponse(url="/dashboard/admin?success=UFR créée avec succès", status_code=302)

@app.post("/admin/create-filiere")
async def admin_create_filiere(
    request: Request,
    admin_username: str = Depends(require_admin),
    nom: str = Form(...),
    code: str = Form(...),
    ufr_id: str = Form(...)
):
    """Admin creates new filière"""
    db = load_db()
    
    # Check if code already exists for this UFR
    existing_filieres = get_filieres_by_ufr(db, ufr_id)
    if any(f["code"] == code for f in existing_filieres):
        return RedirectResponse(url="/dashboard/admin?error=Code filière déjà existant pour cette UFR", status_code=302)
    
    # Create new filière
    new_filiere = {
        "id": str(uuid.uuid4()),
        "nom": nom,
        "code": code,
        "ufr_id": ufr_id
    }
    
    if "filieres" not in db:
        db["filieres"] = []
    db["filieres"].append(new_filiere)
    save_db(db)
    
    return RedirectResponse(url="/dashboard/admin?success=Filière créée avec succès", status_code=302)

@app.post("/admin/create-matiere")
async def admin_create_matiere(
    request: Request,
    admin_username: str = Depends(require_admin),
    nom: str = Form(...),
    code: str = Form(...),
    filiere_id: str = Form(...)
):
    """Admin creates new matière"""
    db = load_db()
    
    # Check if code already exists for this filière
    existing_matieres = get_matieres_by_filiere(db, filiere_id)
    if any(m["code"] == code for m in existing_matieres):
        return RedirectResponse(url="/dashboard/admin?error=Code matière déjà existant pour cette filière", status_code=302)
    
    # Create new matière
    new_matiere = {
        "id": str(uuid.uuid4()),
        "nom": nom,
        "code": code,
        "filiere_id": filiere_id
    }
    
    if "matieres" not in db:
        db["matieres"] = []
    db["matieres"].append(new_matiere)
    save_db(db)
    
    return RedirectResponse(url="/dashboard/admin?success=Matière créée avec succès", status_code=302)

# API endpoints for hierarchical data
@app.get("/api/ufrs/{universite_id}")
async def get_ufrs_api(universite_id: str):
    """Get UFRs for a specific university"""
    db = load_db()
    ufrs = get_ufrs_by_universite(db, universite_id)
    return {"ufrs": ufrs}

@app.get("/api/filieres/{ufr_id}")
async def get_filieres_api(ufr_id: str):
    """Get filières for a specific UFR"""
    db = load_db()
    filieres = get_filieres_by_ufr(db, ufr_id)
    return {"filieres": filieres}

@app.get("/api/matieres/{filiere_id}")
async def get_matieres_api(filiere_id: str):
    """Get matières for a specific filière"""
    db = load_db()
    matieres = get_matieres_by_filiere(db, filiere_id)
    return {"matieres": matieres}

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
