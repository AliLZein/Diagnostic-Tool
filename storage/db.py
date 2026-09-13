from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import os
import sys
if getattr(sys, "frozen", False):
    # Running as a PyInstaller exe
    BASE_DIR = os.path.dirname(sys.executable)
else:
    # Running as a plain .py script — go up one level from storage/
    BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
 
DATA_DIR = os.path.join(BASE_DIR, "data")
os.makedirs(DATA_DIR, exist_ok=True)
 
DB_FILE = os.path.join(DATA_DIR, "findings.db")
DB_PATH = f"sqlite:///{DB_FILE}"
 
engine = create_engine(DB_PATH, echo=False)
 
Base = declarative_base()
 
class Finding(Base):
    __tablename__ = "findings"
 
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    category = Column(String(50))
    severity = Column(String(20))
    source = Column(String(100))
    message = Column(Text)
 
Base.metadata.create_all(engine)
Session = sessionmaker(bind=engine)
 
def log_finding(category, severity, source, message):
    session = Session()
    finding = Finding(category=category, severity=severity, source=source, message=message)
    session.add(finding)
    session.commit()
    session.close()
    # Use logging, not print — print() crashes silently in a windowed
    # PyInstaller build where sys.stdout is None (unless you've already
    # patched stdout, as in your desktop_app.py — this is just extra safety).
    import logging
    logging.info(f"[{severity.upper()}] {category} — {source}: {message}")
 
def get_all_findings():
    session = Session()
    results = session.query(Finding).order_by(Finding.timestamp.desc()).all()
    session.close()
    return results
