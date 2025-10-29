# Employee Onboarding (US) - FastAPI + Jinja2

Single-repo FastAPI app with server-side rendered templates for US onboarding.

## Run locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open http://127.0.0.1:8000

## Environment

- `APP_SECRET_KEY` (optional): overrides generated cookie signing key

## Pages

- `/` Home
- `/register` Registration form (personal info + I-9 basics)
- `/upload/{employee_id}` Document upload page
- `/status/{employee_id}` Pending/verified status page
- `/login` Login via Employee ID (post-verification)
- `/profile` Employee profile (read-only)

## Data

- SQLite file: `onboarding.sqlite3`
- Uploads directory: `uploads/` (not tracked)

## Notes

- Identity verification and I-9 checks are simplified mocks for demonstration.
- Allowed uploads: PDF/PNG/JPG up to 10MB.
- Cookie-based simple session using signed token.

