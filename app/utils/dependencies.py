from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from app.db.models import User
from app.auth.auth import verify_access_token
from app.db.base import get_db


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_current_user(db: Session = Depends(get_db), token: str = Depends(oauth2_scheme), required_role: str = "admin"):
    if required_role == "user":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    payload = verify_access_token(token, required_role)
    username = payload.get("sub")
    user = db.query(User).filter(User.username == username).first()
    
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    return user
