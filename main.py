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
            "users": {"prof": [], "etudiant": []},
            "contents": [],
            "payments": [],
            "subscriptions": []
        }
        save_db(initial_db)
        return initial_db
    
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_SH)  # Shared lock for reading
            data = json.load(f)
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)  # Unlock
        return data
    except (json.JSONDecodeError, FileNotFoundError):
        # Return empty structure if file is corrupted
        return {
            "users": {"prof": [], "etudiant": []},
            "contents": [],
            "payments": [],
            "subscriptions": []
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

# Routes
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Home page with registration forms"""
    user = get_current_user(request)
    if user:
        role, username = user
        if role == "prof":
            return RedirectResponse(url="/dashboard/prof", status_code=302)
        else:
            return RedirectResponse(url="/dashboard/etudiant", status_code=302)
    
    return templates.TemplateResponse("index.html", {"request": request})

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
    if find_user(username, "prof") or find_user(username, "etudiant"):
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
    universite: str = Form(...),
    filiere: str = Form(...),
    niveau: str = Form(...)
):
    """Register new student"""
    db = load_db()
    
    # Check if username already exists
    if find_user(username, "prof") or find_user(username, "etudiant"):
        return templates.TemplateResponse(
            "index.html", 
            {"request": request, "error": "Ce nom d'utilisateur existe déjà"}
        )
    
    # Create new student
    new_etudiant = {
        "username": username,
        "password_hash": hash_password(password),
        "nom": nom,
        "prenom": prenom,
        "universite": universite,
        "filiere": filiere,
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
        else:
            return RedirectResponse(url="/dashboard/etudiant", status_code=302)
    
    return templates.TemplateResponse("login.html", {"request": request})

@app.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...)
):
    """Process login"""
    # Try professor first
    user = find_user(username, "prof")
    role = "prof"
    
    if not user:
        # Try student
        user = find_user(username, "etudiant")
        role = "etudiant"
    
    if not user or not verify_password(password, user["password_hash"]):
        return templates.TemplateResponse(
            "login.html", 
            {"request": request, "error": "Nom d'utilisateur ou mot de passe incorrect"}
        )
    
    # Create session and redirect
    session_token = create_session_token(username, role)
    redirect_url = "/dashboard/prof" if role == "prof" else "/dashboard/etudiant"
    
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
    
    prof = find_user(prof_username, "prof")
    
    return templates.TemplateResponse("dashboard_prof.html", {
        "request": request,
        "prof": prof,
        "contents": prof_contents
    })

@app.post("/prof/content")
async def create_content(
    request: Request,
    prof_username: str = Depends(require_prof),
    type: str = Form(...),
    universite: str = Form(...),
    filiere: str = Form(...),
    niveau: str = Form(...),
    semestre: str = Form(...),
    matiere: str = Form(...),
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
        "universite": universite,
        "filiere": filiere,
        "niveau": niveau,
        "semestre": semestre,
        "matiere": matiere,
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
    
    # Get all available semesters (S1-S10 for now)
    all_semesters = [f"S{i}" for i in range(1, 11)]
    
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
    subjects = list(set([c["matiere"] for c in accessible_content]))
    chapters = list(set([c["chapitre"] for c in accessible_content]))
    
    return templates.TemplateResponse("dashboard_etudiant.html", {
        "request": request,
        "student": student,
        "semester_status": semester_status,
        "accessible_content": accessible_content,
        "subjects": subjects,
        "chapters": chapters,
        "price": PRICE_FCFA
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
