from __future__ import annotations

import hashlib
import re
import logging
from datetime import date


def generate_employee_id(first_name: str, last_name: str, dob: date) -> str:
    base = f"{first_name}{last_name}{dob.isoformat()}".lower()
    digest = hashlib.sha256(base.encode()).hexdigest()[:10]
    return f"EMP{digest.upper()}"


def verify_identity(name: str, dob: date, ssn_last4: str) -> tuple[bool, str | None]:
    if not re.fullmatch(r"\d{4}", ssn_last4 or ""):
        logging.warning(f"Invalid SSN format for identity verification: {name}")
        return False, "SSN last 4 must be exactly 4 digits."
    # Simulated identity check: deterministic pseudo-check
    seed = f"{name}|{dob.isoformat()}|{ssn_last4}"
    ok = int(hashlib.md5(seed.encode()).hexdigest(), 16) % 7 != 0
    if not ok:
        logging.warning(f"Identity verification failed for: {name}")
    else:
        logging.info(f"Identity verification successful for: {name}")
    return (True, None) if ok else (False, "Automated identity check could not verify the information.")


def validate_i9(attestation: str | None, document_list: str | None, document_desc: str | None) -> tuple[bool, str | None]:
    if not attestation:
        return False, "I-9 Section 1 attestation is required."
    if document_list not in {"A", "B", "C"}:
        return False, "I-9 document list must be A, B, or C."
    if not document_desc or len(document_desc.strip()) < 3:
        return False, "Provide a brief description or identifier for the document."
    return True, None

