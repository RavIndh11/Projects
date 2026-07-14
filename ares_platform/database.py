from sqlalchemy import create_engine, Column, Integer, String, JSON, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import chromadb
import os

# Ensure data directory exists for Docker volumes
os.makedirs("data", exist_ok=True)

# Create SQLite Database (Relational) - Stored in the persistent volume
DATABASE_URL = "sqlite:///./data/ares_state.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class SessionLog(Base):
    """Stores the history of engagements."""
    __tablename__ = "session_logs"

    id = Column(Integer, primary_key=True, index=True)
    target_ip = Column(String, index=True)
    start_time = Column(DateTime, default=datetime.utcnow)
    status = Column(String, default="running")
    final_report = Column(String, nullable=True)

class VulnerabilityFindings(Base):
    """Stores relational findings for the UI."""
    __tablename__ = "vulnerability_findings"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(Integer, index=True)
    service = Column(String)
    vulnerability = Column(String)
    severity = Column(String)
    approved = Column(String, default="pending") # pending, approved, denied

# Initialize ChromaDB (Vector DB for RAG) - Stored in the persistent volume
chroma_client = chromadb.PersistentClient(path="./data/chroma_db")
cve_collection = chroma_client.get_or_create_collection(name="cve_knowledgebase")

def init_db():
    Base.metadata.create_all(bind=engine)

    # Pre-seed ChromaDB with some dummy exploit knowledge if empty
    if cve_collection.count() == 0:
        cve_collection.add(
            documents=[
                "Apache 2.4.49 path traversal vulnerability CVE-2021-41773. Exploit payload: curl -v --path-as-is http://target/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
                "vsftpd 2.3.4 backdoor CVE-2011-2523. Exploit triggers by sending a username ending with a smiley face :)",
                "Tomcat default credentials (tomcat:tomcat, admin:admin) can be used to deploy a WAR file and get a reverse shell."
            ],
            metadatas=[{"cve": "CVE-2021-41773"}, {"cve": "CVE-2011-2523"}, {"type": "misconfig"}],
            ids=["1", "2", "3"]
        )
