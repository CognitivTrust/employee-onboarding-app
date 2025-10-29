from __future__ import annotations
from datetime import datetime, date
from sqlalchemy import String, Integer, Date, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


class Employee(Base):
    __tablename__ = "employees"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    employee_id: Mapped[str] = mapped_column(String(16), unique=True, index=True)

    first_name: Mapped[str] = mapped_column(String(100))
    last_name: Mapped[str] = mapped_column(String(100))
    dob: Mapped[date] = mapped_column(Date)
    ssn_last4: Mapped[str] = mapped_column(String(4))

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

