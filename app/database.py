from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, DeclarativeBase
import os
from cryptography.fernet import Fernet


DATABASE_URL = "sqlite:///./onboarding.sqlite3"

# Ensure encryption key is set
if "ENCRYPTION_KEY" not in os.environ:
    os.environ["ENCRYPTION_KEY"] = Fernet.generate_key().decode()


class Base(DeclarativeBase):
    pass


engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

