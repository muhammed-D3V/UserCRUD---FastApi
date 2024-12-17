from pydantic import BaseModel, EmailStr, Field, field_validator
from typing import Optional
from app.db.models import RoleEnum

class UserCreate(BaseModel):
    username: str = Field(..., max_length=50, description="Username must be less than 50 characters")
    password: str
    email: EmailStr
    phone_number: str = Field(..., pattern=r"^\d{10}$", description="Phone number must be exactly 10 digits")
    role: Optional[str] = "user"

    @field_validator("password")
    def validate_password(cls, value):
        if len(value) < 8:
            raise ValueError("Password must be at least 8 characters long")
        if not any(char.isupper() for char in value):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(char.islower() for char in value):
            raise ValueError("Password must contain at least one lowercase letter")
        if not any(char.isdigit() for char in value):
            raise ValueError("Password must contain at least one digit")
        if not any(char in "!@#$%^&*()-_+=" for char in value):
            raise ValueError("Password must contain at least one special character (!@#$%^&*()-_+=)")
        return value

class BasicUserInfoForLogin(BaseModel):
    username: str
    password: str

class RetriveUsersModel(BaseModel):
    id: int
    username: str 
    email: EmailStr
    phone_number: str 
    role: str

class UpdateUserModel(BaseModel):
    username: Optional[str] = None  # Make username optional
    email: Optional[EmailStr] = None  # Make email optional
    phone_number: Optional[str] = None  # Make phone_number optional
    role: Optional[str] = None  # Make role optional

    @field_validator('role')
    def validate_role(cls, v):
        if v and v not in [role.value for role in RoleEnum]:
            raise ValueError("Invalid role")
        return v