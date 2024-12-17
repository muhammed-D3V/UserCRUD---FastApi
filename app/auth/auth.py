from sqlalchemy.orm import Session
from app.db.models import User
from app.utils.security import verify_password
from typing import Dict
import time
import jwt
from app.db.models import RoleEnum
from datetime import datetime, timedelta
from fastapi import HTTPException, status
from app.config import settings

def create_access_token(user_data: dict) -> str:  
    expiration_time = datetime.now() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    print(settings.ACCESS_TOKEN_EXPIRE_MINUTES, "#########################")
    # Convert expiration time to human-readable format
    human_readable_expiry = expiration_time.strftime("%Y-%m-%d %H:%M:%S %Z")
    print(f"Access Token Expiration: {human_readable_expiry}")

    to_encode = {
        "sub": user_data.username,
        "email": user_data.email,
        "phone_number": user_data.phone_number,
        "role": user_data.role.value if isinstance(user_data.role, RoleEnum) else user_data.role,
        "exp": int(expiration_time.timestamp()),  # Convert to timestamp
        "iat": int(datetime.now().timestamp()),  # Convert to timestamp
        "human_readable_expiry": human_readable_expiry  # Added for reference
    }

    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def create_refresh_token(data: dict) -> str:
    expiration_time = datetime.now() + timedelta(minutes=settings.REFRESH_TOKEN_EXPIRE_MINUTES)
    
    human_readable_expiry = expiration_time.strftime("%Y-%m-%d %H:%M:%S %Z")
    print(f"Refresh Token Expiration: {human_readable_expiry}")

    to_encode = data.copy()
    to_encode.update({
        "exp": int(expiration_time.timestamp()),  
        "iat": int(datetime.now().timestamp()),  
        "sub": data["sub"],
        "human_readable_expiry": human_readable_expiry  
    })

    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm="HS256")
    return encoded_jwt

def authenticate_user(db: Session, username: str, password: str):
    user = db.query(User).filter(User.username == username).first()
    if user and verify_password(password, user.password):
        return user
    return None


def verify_refresh_token(refresh_token: str) -> dict:
    try:
        decoded_token = jwt.decode(
            refresh_token, 
            settings.SECRET_KEY, 
            algorithms=["HS256"]
        )
        
        return decoded_token
    
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Refresh token expired")
    
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=f"Invalid refresh token: {str(e)}")
    

def verify_access_token(access_token: str, required_role: str = "user"):
    try:
        decoded_token = jwt.decode(
            access_token, 
            settings.SECRET_KEY, 
            algorithms=["HS256"]
        )

        exp_timestamp = decoded_token.get("exp")
        if exp_timestamp and exp_timestamp < datetime.utcnow().timestamp():
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access token expired")

        if decoded_token.get("role") != required_role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access forbidden for users with role: {decoded_token.get('role')}"
            )

        return decoded_token 
    
    # except jwt.ExpiredSignatureError:
    #     raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access token expired")
    
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Invalid access token")