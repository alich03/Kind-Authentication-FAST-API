from sqlalchemy import create_engine, Column, String,Integer
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Set up the database URL
DATABASE_URL = "sqlite:///./user.db"  # For SQLite
# For PostgreSQL, use DATABASE_URL = "postgresql://user:password@localhost/dbname"

# Create the SQLAlchemy engine and session
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Define a User model
class User(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    auth_id = Column(String, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    first_name = Column(String)
    last_name = Column(String)
    
    

# Create the tables in the database
Base.metadata.create_all(bind=engine)

# Dependency to get the session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()