from sqlalchemy import create_engine, Column, String, Integer, DateTime, Text, Boolean
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime

import os

DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./secureline.db")

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    public_key = Column(Text, nullable=True)          # X25519 public key (hex)
    device_fingerprint = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True, index=True)
    event = Column(String, nullable=False)
    actor = Column(String, nullable=False)
    detail = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    prev_hash = Column(String, nullable=False)
    current_hash = Column(String, nullable=False)
    tampered = Column(Boolean, default=False)


class ThreatLog(Base):
    __tablename__ = "threat_logs"
    id = Column(Integer, primary_key=True, index=True)
    actor = Column(String, nullable=False)
    threat_type = Column(String, nullable=False)
    detail = Column(Text, nullable=True)
    severity = Column(String, default="LOW")
    timestamp = Column(DateTime, default=datetime.utcnow)


def init_db():
    Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
