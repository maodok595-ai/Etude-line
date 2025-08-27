import json
import os
import uuid
from datetime import datetime, timedelta
from typing import Optional, Dict, Any, List, Tuple
import fcntl
from pathlib import Path

from fastapi import FastAPI, Request, Form, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, validator
from passlib.context import CryptContext
from itsdangerous import URLSafeTimedSerializer
import uvicorn

# Initialize FastAPI app
app = FastAPI(title="Étude LINE", description="Application éducative avec système de paiement")
templates = Jinja2Templates(directory="templates")

# Configuration from environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "your-super-secret-key-change-this")
PRICE_FCFA = int(os.getenv("PRICE_FCFA", "990"))
WAVE_WEBHOOK_SECRET = os.getenv("WAVE_WEBHOOK_SECRET", "")
WAVE_QR_IMAGE_PATH = os.getenv("WAVE_QR_IMAGE_PATH", "templates/wave_qr.png")

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
    created_by: str  # username du prof

class Payment(BaseModel):
    id: str
    username: str
    semestre: str
    amount: int
    provider: str
    status: str
    paid_at: datetime
    raw: Dict[str, Any]

class Subscription(BaseModel):
    username: str
    semestre: str
    paid_at: datetime
    expires_at: datetime

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
            "payments": [],
            "subscriptions": [],
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
            "payments": [],
            "subscriptions": [],
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
    """Get student profile"""
    user = find_user(username, "etudiant")
    if user:
        return {
            "username": user["username"],
            "nom": user["nom"],
            "prenom": user["prenom"],
            "universite": user["universite"],
            "filiere": user["filiere"],
            "niveau": user["niveau"]
        }
    return None

def is_subscription_active(username: str, semestre: str) -> bool:
    """Check if subscription is active for user and semester"""
    db = load_db()
    now = now_utc()
    
    for sub in db["subscriptions"]:
        if (sub["username"] == username and 
            sub["semestre"] == semestre and 
            datetime.fromisoformat(sub["expires_at"]) > now):
            return True
    return False

def get_accessible_content(username: str) -> List[Dict[str, Any]]:
    """Get content accessible to student based on active subscriptions"""
    db = load_db()
    student = get_student_profile(username)
    if not student:
        return []
    
    accessible_content = []
    
    for content in db["contents"]:
        # Check if content matches student profile
        if (content["universite"] == student["universite"] and
            content["filiere"] == student["filiere"] and
            content["niveau"] == student["niveau"]):
            
            # Check if student has active subscription for this semester
            if is_subscription_active(username, content["semestre"]):
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
    texte: str = Form(...)
):
    """Create new content"""
    db = load_db()
    
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
        "created_by": prof_username
    }
    
    db["contents"].append(new_content)
    save_db(db)
    
    return RedirectResponse(url="/dashboard/prof", status_code=302)

@app.get("/dashboard/etudiant", response_class=HTMLResponse)
async def dashboard_etudiant(request: Request, etudiant_username: str = Depends(require_etudiant)):
    """Student dashboard"""
    db = load_db()
    student = get_student_profile(etudiant_username)
    
    if not student:
        raise HTTPException(status_code=404, detail="Student profile not found")
    
    # Get all available semesters (S1-S2 only per level)
    all_semesters = ["S1", "S2"]
    
    # Check subscription status for each semester
    semester_status = {}
    for sem in all_semesters:
        is_active = is_subscription_active(etudiant_username, sem)
        expires_at = None
        
        if is_active:
            # Find expiration date
            for sub in db["subscriptions"]:
                if (sub["username"] == etudiant_username and 
                    sub["semestre"] == sem and 
                    datetime.fromisoformat(sub["expires_at"]) > now_utc()):
                    expires_at = datetime.fromisoformat(sub["expires_at"])
                    break
        
        semester_status[sem] = {
            "active": is_active,
            "expires_at": expires_at
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
        "price": PRICE_FCFA,
        "universites": universites,
        "ufrs": ufrs,
        "filieres": filieres,
        "matieres": matieres
    })

@app.post("/pay/start")
async def start_payment(
    request: Request,
    etudiant_username: str = Depends(require_etudiant),
    semestre: str = Form(...)
):
    """Start payment process"""
    # This would typically create a payment intention
    # For now, we'll just return to dashboard with payment modal info
    return RedirectResponse(url=f"/dashboard/etudiant?pay_semestre={semestre}", status_code=302)

@app.post("/pay/confirm-manual")
async def confirm_manual_payment(
    request: Request,
    etudiant_username: str = Depends(require_etudiant),
    semestre: str = Form(...),
    transaction_id: str = Form(...)
):
    """Confirm manual payment (test mode)"""
    if not transaction_id.strip():
        return RedirectResponse(url="/dashboard/etudiant?error=Transaction ID requis", status_code=302)
    
    db = load_db()
    now = now_utc()
    
    # Create payment record
    payment = {
        "id": str(uuid.uuid4()),
        "username": etudiant_username,
        "semestre": semestre,
        "amount": PRICE_FCFA,
        "provider": "WAVE",
        "status": "succeeded",
        "paid_at": now,
        "raw": {"transaction_id": transaction_id, "manual": True}
    }
    
    db["payments"].append(payment)
    
    # Create or update subscription
    expires_at = add_days(now, 30)
    
    # Remove existing subscription for this semester if any
    db["subscriptions"] = [s for s in db["subscriptions"] 
                          if not (s["username"] == etudiant_username and s["semestre"] == semestre)]
    
    # Add new subscription
    subscription = {
        "username": etudiant_username,
        "semestre": semestre,
        "paid_at": now,
        "expires_at": expires_at
    }
    
    db["subscriptions"].append(subscription)
    save_db(db)
    
    return RedirectResponse(url="/dashboard/etudiant?success=Paiement confirmé, accès activé!", status_code=302)

@app.post("/webhook/wave")
async def wave_webhook(request: Request):
    """Wave webhook handler (for real payment integration)"""
    # TODO: Implement real Wave webhook handling
    # This is a placeholder for when Wave webhook is configured
    
    if not WAVE_WEBHOOK_SECRET:
        return {"status": "error", "message": "Webhook secret not configured"}
    
    try:
        # Get webhook signature from headers
        signature = request.headers.get("WAVE_SIGNATURE", "")
        
        # Get request body
        body = await request.body()
        
        # TODO: Verify signature with WAVE_WEBHOOK_SECRET
        # TODO: Parse webhook payload according to Wave API documentation
        # TODO: Handle payment.succeeded event
        # TODO: Create Payment and Subscription records
        
        # For now, return success
        return {"status": "ok"}
        
    except Exception as e:
        return {"status": "error", "message": str(e)}

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
    print(f"💰 Prix par semestre: {PRICE_FCFA} FCFA")
    print(f"🔗 Webhook Wave URL: http://0.0.0.0:5000/webhook/wave")
    
    if not WAVE_WEBHOOK_SECRET:
        print("⚠️  WAVE_WEBHOOK_SECRET non configuré - mode manuel seulement")
    
    print("=" * 50)
    
    uvicorn.run(app, host="0.0.0.0", port=5000, reload=True)
