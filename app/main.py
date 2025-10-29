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

from .database import Base, engine, get_db
from .models import Employee, Document
from .verification import verify_identity, validate_i9, generate_employee_id
from .auth import set_session, clear_session, get_current_employee_id


BASE_DIR = Path(__file__).resolve().parent.parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"
UPLOADS_DIR = BASE_DIR / "uploads"

for d in (TEMPLATES_DIR, STATIC_DIR, UPLOADS_DIR):
    d.mkdir(parents=True, exist_ok=True)

# Initialize DB
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Employee Onboarding (US)")

app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))


SECRET_KEY = os.environ.get("APP_SECRET_KEY", secrets.token_hex(16))


def render(request: Request, template: str, context: dict) -> HTMLResponse:
    return templates.TemplateResponse(template, {"request": request, **context})


@app.middleware("http")
async def add_security_headers(request, call_next):
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
def register_submit(
    request: Request,
    first_name: str = Form(...),
    last_name: str = Form(...),
    dob: str = Form(...),
    ssn_last4: str = Form(...),
    email: str | None = Form(None),
    phone: str | None = Form(None),
    i9_attestation: str = Form(...),
    i9_list: str = Form(...),
    i9_desc: str = Form(...),
    db: Session = Depends(get_db),
):
    errors: list[str] = []
    try:
        dob_date = date.fromisoformat(dob)
    except Exception:
        errors.append("DOB must be in YYYY-MM-DD format.")
        return render(request, "register.html", {"errors": errors})

    ok, msg = verify_identity(f"{first_name} {last_name}", dob_date, ssn_last4)
    if not ok:
        errors.append(msg or "Identity verification failed.")
    ok, msg = validate_i9(i9_attestation, i9_list, i9_desc)
    if not ok:
        errors.append(msg or "I-9 validation failed.")

    if errors:
        return render(request, "register.html", {"errors": errors})

    emp = Employee(
        employee_id=generate_employee_id(first_name, last_name, dob_date),
        first_name=first_name.strip(),
        last_name=last_name.strip(),
        dob=dob_date,
        ssn_last4=ssn_last4,
        email=email,
        phone=phone,
        i9_section1_attestation=i9_attestation,
        i9_document_list=i9_list,
        i9_document_desc=i9_desc,
        verification_status="pending",
    )
    db.add(emp)
    db.commit()
    db.refresh(emp)

    return RedirectResponse(url=f"/upload/{emp.employee_id}", status_code=303)


@app.get("/upload/{employee_id}", response_class=HTMLResponse)
def upload_form(employee_id: str, request: Request, db: Session = Depends(get_db)):
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
    kind: str = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
):
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
def login_submit(request: Request, employee_id: str = Form(...), db: Session = Depends(get_db)):
    emp = db.query(Employee).filter_by(employee_id=employee_id.strip()).first()
    if not emp or emp.verification_status != "verified":
        return render(request, "login.html", {"error": "Employee not found or not verified yet."})
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
    employee_id = get_current_employee_id(request, SECRET_KEY)
    if not employee_id:
        return RedirectResponse(url="/login", status_code=303)
    emp = db.query(Employee).filter_by(employee_id=employee_id).first()
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


