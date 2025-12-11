from __future__ import annotations

import logging
import os
import secrets
from datetime import date
from pathlib import Path

from fastapi import FastAPI, Depends, Request, Form, UploadFile, File, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session
from passlib.context import CryptContext
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from fastapi_csrf_protect import CsrfProtect
from pydantic import BaseModel, validator, EmailStr, Field
import logging
import re

from .database import Base, engine, get_db
from .models import Employee, Document
from .verification import verify_identity, validate_i9, generate_employee_id
from .auth import set_session, clear_session, get_current_employee_id

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Rate limiting
limiter = Limiter(key_func=get_remote_address)

# CSRF Protection
@CsrfProtect.load_config
def get_csrf_config():
    return [("secret_key", SECRET_KEY), ("max_age", 3600)]


# Pydantic models for input validation
class RegisterForm(BaseModel):
    first_name: str = Field(..., min_length=1, max_length=100)
    last_name: str = Field(..., min_length=1, max_length=100)
    dob: str = Field(..., regex=r'^\d{4}-\d{2}-\d{2}$')
    ssn_last4: str = Field(..., regex=r'^\d{4}$')
    password: str = Field(..., min_length=8)
    email: EmailStr | None = None
    phone: str | None = Field(None, regex=r'^\+?1?[-.\s]?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}$')
    i9_attestation: str = Field(..., min_length=1)
    i9_list: str = Field(..., regex=r'^[A-C]$')
    i9_desc: str = Field(..., min_length=1, max_length=255)

    @validator('first_name', 'last_name')
    def validate_name(cls, v):
        if not re.match(r'^[a-zA-Z\s\-]+$', v):
            raise ValueError('Name must contain only letters, spaces, and hyphens')
        return v.strip()

    @validator('password')
    def validate_password(cls, v):
        if not re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$', v):
            raise ValueError('Password must be at least 8 characters with uppercase, lowercase, number, and special character')
        return v


class LoginForm(BaseModel):
    employee_id: str = Field(..., min_length=1, max_length=16)
    password: str = Field(..., min_length=1)


BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
UPLOADS_DIR = BASE_DIR / "uploads"

for d in (TEMPLATES_DIR, STATIC_DIR, UPLOADS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Initialize DB
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Employee Onboarding (US)")

# Add rate limiting middleware
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


SECRET_KEY = os.environ.get("APP_SECRET_KEY", secrets.token_hex(16))


def render(request: Request, template: str, context: dict) -> HTMLResponse:
    return templates.TemplateResponse(template, {"request": request, **context})


def get_current_employee(request: Request, db: Session = Depends(get_db)) -> Employee | None:
    employee_id = get_current_employee_id(request, SECRET_KEY)
    if not employee_id:
        return None
    return db.query(Employee).filter_by(employee_id=employee_id).first()


@app.middleware("http")
async def enforce_https(request, call_next):
    if request.headers.get("x-forwarded-proto") == "http":
        url = request.url.replace(scheme="https")
        return RedirectResponse(url=url, status_code=301)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return render(request, "home.html", {})


@app.get("/register", response_class=HTMLResponse)
def register_form(request: Request):
    return render(request, "register.html", {"errors": []})


@app.post("/register")
@limiter.limit("3/minute")
def register_submit(
    request: Request,
    csrf_protect: CsrfProtect = Depends(),
    form_data: RegisterForm = Depends(),
    db: Session = Depends(get_db),
):
    csrf_protect.validate_csrf(request)
    errors: list[str] = []
    try:
        dob_date = date.fromisoformat(form_data.dob)
    except Exception:
        errors.append("DOB must be in YYYY-MM-DD format.")
        return render(request, "register.html", {"errors": errors})

    ok, msg = verify_identity(f"{form_data.first_name} {form_data.last_name}", dob_date, form_data.ssn_last4)
    if not ok:
        errors.append(msg or "Identity verification failed.")
    ok, msg = validate_i9(form_data.i9_attestation, form_data.i9_list, form_data.i9_desc)
    if not ok:
        errors.append(msg or "I-9 validation failed.")

    if errors:
        return render(request, "register.html", {"errors": errors})

    emp = Employee(
        employee_id=generate_employee_id(form_data.first_name, form_data.last_name, dob_date),
        first_name=form_data.first_name.strip(),
        last_name=form_data.last_name.strip(),
        dob=dob_date,
        ssn_last4=form_data.ssn_last4,
        password_hash=pwd_context.hash(form_data.password),
        email=form_data.email,
        phone=form_data.phone,
        i9_section1_attestation=form_data.i9_attestation,
        i9_document_list=form_data.i9_list,
        i9_document_desc=form_data.i9_desc,
        verification_status="pending",
    )
    db.add(emp)
    db.commit()
    db.refresh(emp)

    return RedirectResponse(url=f"/upload/{emp.employee_id}", status_code=303)


@app.get("/upload/{employee_id}", response_class=HTMLResponse)
def upload_form(employee_id: str, request: Request, db: Session = Depends(get_db)):
    current_emp = get_current_employee(request, db)
    if not current_emp or current_emp.employee_id != employee_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    emp = db.query(Employee).filter_by(employee_id=employee_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    return render(request, "upload.html", {"emp": emp, "errors": []})


ALLOWED_EXTS = {"pdf", "png", "jpg", "jpeg"}


def secure_filename(filename: str) -> str:
    name = os.path.basename(filename).replace("\\", "/").split("/")[-1]
    keep = [c for c in name if c.isalnum() or c in {"_", "-", "."}]
    sanitized = "".join(keep).strip(".")
    return sanitized or "file"


@app.post("/upload/{employee_id}")
async def upload_submit(
    employee_id: str,
    request: Request,
    csrf_protect: CsrfProtect = Depends(),
    kind: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
    csrf_protect.validate_csrf(request)
    current_emp = get_current_employee(request, db)
    if not current_emp or current_emp.employee_id != employee_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    emp = db.query(Employee).filter_by(employee_id=employee_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")

    ext = (file.filename or "").rsplit(".", 1)[-1].lower()
    if ext not in ALLOWED_EXTS:
        return render(request, "upload.html", {"emp": emp, "errors": ["Only PDF/PNG/JPG files are allowed."]})

    safe_name = secure_filename(file.filename or "upload")
    unique_name = f"{emp.employee_id}_{secrets.token_hex(6)}_{safe_name}"
    dest = UPLOADS_DIR / unique_name
    content = await file.read()
    if len(content) > 10 * 1024 * 1024:
        return render(request, "upload.html", {"emp": emp, "errors": ["File too large (max 10MB)."]})
    with open(dest, "wb") as f:
        f.write(content)

    doc = Document(employee_id_fk=emp.id, kind=kind, filename=safe_name, stored_path=str(dest))
    db.add(doc)
    db.commit()

    # Simple heuristic: if at least one doc uploaded, mark under-review
    if emp.verification_status == "pending":
        emp.verification_status = "under_review"
        db.add(emp)
        db.commit()

    return RedirectResponse(url=f"/status/{emp.employee_id}", status_code=303)


@app.get("/status/{employee_id}", response_class=HTMLResponse)
def status_page(employee_id: str, request: Request, db: Session = Depends(get_db)):
    current_emp = get_current_employee(request, db)
    if not current_emp or current_emp.employee_id != employee_id:
        raise HTTPException(status_code=403, detail="Forbidden")
    emp = db.query(Employee).filter_by(employee_id=employee_id).first()
    if not emp:
        raise HTTPException(status_code=404, detail="Employee not found")
    # Auto-approve when at least 2 documents exist (mock automation)
    if emp.verification_status in {"pending", "under_review"} and len(emp.documents) >= 2:
        emp.verification_status = "verified"
        db.add(emp)
        db.commit()
    return render(request, "status.html", {"emp": emp})


@app.get("/login", response_class=HTMLResponse)
def login_form(request: Request):
    return render(request, "login.html", {"error": None})


@app.post("/login")
@limiter.limit("5/minute")
def login_submit(request: Request, form_data: LoginForm = Depends(), db: Session = Depends(get_db)):
    emp = db.query(Employee).filter_by(employee_id=form_data.employee_id.strip()).first()
    if not emp or emp.verification_status != "verified" or not pwd_context.verify(form_data.password, emp.password_hash):
        logging.warning(f"Failed login attempt for employee_id: {form_data.employee_id} from IP: {request.client.host}")
        return render(request, "login.html", {"error": "Invalid credentials or not verified yet."})
    logging.info(f"Successful login for employee_id: {form_data.employee_id}")
    response = RedirectResponse(url="/profile", status_code=303)
    set_session(response, SECRET_KEY, emp.employee_id)
    return response


@app.get("/logout")
def logout():
    response = RedirectResponse(url="/")
    clear_session(response)
    return response


@app.get("/profile", response_class=HTMLResponse)
def profile(request: Request, db: Session = Depends(get_db)):
    emp = get_current_employee(request, db)
    if not emp:
        return RedirectResponse(url="/login", status_code=303)
    return render(request, "profile.html", {"emp": emp})


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException):
    logging.error("HTTPException %s: %s", exc.status_code, exc.detail)
    if exc.status_code == 404:
        return render(request, "error.html", {"code": 404, "message": "Not found"})
    return render(request, "error.html", {"code": exc.status_code, "message": exc.detail})


@app.get("/healthz")
def healthz():
    return {"ok": True}


