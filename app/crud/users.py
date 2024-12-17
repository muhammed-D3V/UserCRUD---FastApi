from sqlalchemy.orm import Session
from app.db.models import User
from app.schemas.user import UserCreate
from app.utils.security import hash_password

def create_user(db: Session, user:UserCreate):
    existing_user = db.query(User).filter(User.username == user.username , User.email == user.email).first()
    if existing_user:
        raise ValueError("Username or email already exists")
    hashed_password = hash_password(user.password)
    db_user = User(
        username=user.username,
        email=user.email,
        password=hashed_password,
        phone_number=user.phone_number,
        role=user.role
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user