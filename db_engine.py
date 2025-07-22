from sqlalchemy import create_engine, Column, Integer, String, Text, JSON
from sqlalchemy.orm import declarative_base, sessionmaker


DB_PATH = "alerts.db"
db_engine = create_engine(f"sqlite:///{DB_PATH}")
Session = sessionmaker(bind=db_engine)
db_session = Session()
Base = declarative_base()


class alert_object(Base):
    __tablename__ = "alerts"
    id = Column(Integer, primary_key=True)
    status = Column(String, default="New")
    endpoint_name = Column(String, default='localhost')
    severity = Column(String, default='Medium')
    time_created = Column(String)
    rule_name = Column(String)
    rule_id = Column(String)
    alert_source = Column(String)
    rule_description = Column(Text)
    files = Column(JSON)
    event_id = Column(JSON)
    detection_engines = Column(String)
    raw_events = Column(JSON)


Base.metadata.create_all(db_engine)
