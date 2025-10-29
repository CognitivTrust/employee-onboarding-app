from __future__ import annotations

from itsdangerous import URLSafeSerializer, BadSignature
from starlette.requests import Request
from starlette.responses import Response


SESSION_COOKIE_NAME = "emp_session"


def get_signer(secret_key: str) -> URLSafeSerializer:
    return URLSafeSerializer(secret_key, salt="employee-onboarding")


def set_session(response: Response, secret_key: str, employee_id: str) -> None:
    signer = get_signer(secret_key)
    token = signer.dumps({"employee_id": employee_id})
    response.set_cookie(SESSION_COOKIE_NAME, token, httponly=True, samesite="lax")


def clear_session(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME)


def get_current_employee_id(request: Request, secret_key: str) -> str | None:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token:
        return None
    try:
        data = get_signer(secret_key).loads(token)
    except BadSignature:
        return None
    return data.get("employee_id")

