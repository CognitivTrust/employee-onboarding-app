from __future__ import annotations
from datetime import datetime, date
from sqlalchemy import String, Integer, Date, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.ext.hybrid import hybrid_property
from cryptography.fernet import Fernet
import os

from .database import Base

# Generate or load encryption key
ENCRYPTION_KEY = os.environ.get("ENCRYPTION_KEY", Fernet.generate_key())
cipher = Fernet(ENCRYPTION_KEY)


class Employee(Base):
    __tablename__ = "employees"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    employee_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)

    first_name: Mapped[str] = mapped_column(String(100))
    last_name: Mapped[str] = mapped_column(String(100))
    _dob_encrypted: Mapped[str] = mapped_column(String(255), nullable=True)
    _ssn_last4_encrypted: Mapped[str] = mapped_column(String(255), nullable=True)
    password_hash: Mapped[str] = mapped_column(String(128))

    @hybrid_property
    def dob(self) -> date | None:
        if self._dob_encrypted:
            decrypted = cipher.decrypt(self._dob_encrypted.encode()).decode()
            return date.fromisoformat(decrypted)
        return None

    @dob.setter
    def dob(self, value: date | None):
        if value:
            encrypted = cipher.encrypt(value.isoformat().encode()).decode()
            self._dob_encrypted = encrypted
        else:
            self._dob_encrypted = None

    @hybrid_property
    def ssn_last4(self) -> str | None:
        if self._ssn_last4_encrypted:
            return cipher.decrypt(self._ssn_last4_encrypted.encode()).decode()
        return None

    @ssn_last4.setter
    def ssn_last4(self, value: str | None):
        if value:
            encrypted = cipher.encrypt(value.encode()).decode()
            self._ssn_last4_encrypted = encrypted
        else:
            self._ssn_last4_encrypted = None

    email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    phone: Mapped[str | None] = mapped_column(String(50), nullable=True)

    i9_section1_attestation: Mapped[str | None] = mapped_column(String(50), nullable=True)
    i9_document_list: Mapped[str | None] = mapped_column(String(1), nullable=True)  # A/B/C
    i9_document_desc: Mapped[str | None] = mapped_column(String(255), nullable=True)

    verification_status: Mapped[str] = mapped_column(String(32), default="pending", index=True)
    verification_notes: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    documents: Mapped[list[Document]] = relationship("Document", back_populates="employee", cascade="all, delete-orphan")


class Document(Base):
    __tablename__ = "documents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    employee_id_fk: Mapped[int] = mapped_column(Integer, ForeignKey("employees.id", ondelete="CASCADE"), index=True)
    kind: Mapped[str] = mapped_column(String(50))  # ssn, passport, i9A, i9B, i9C, other
    filename: Mapped[str] = mapped_column(String(255))
    stored_path: Mapped[str] = mapped_column(String(500))
    uploaded_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    employee: Mapped[Employee] = relationship("Employee", back_populates="documents")

