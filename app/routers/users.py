from fastapi import APIRouter, HTTPException, Depends, status
from sqlalchemy.orm import Session
from app.db.base import get_db
from app.schemas.user import UserCreate, BasicUserInfoForLogin,RetriveUsersModel, UpdateUserModel
from app.crud.users import create_user
from typing import Annotated
from app.auth.auth import create_access_token, authenticate_user,create_refresh_token, verify_refresh_token
from fastapi.responses import JSONResponse
from app.db.models import User
from typing import List
from app.utils.dependencies import get_current_user
from app.db.models import RoleEnum

router = APIRouter()
db_dependency = Annotated[Session, Depends(get_db)]
auth_dependency = Annotated[User, Depends(get_current_user)]

@router.post('/users/', response_model=dict, status_code=status.HTTP_201_CREATED)
def register_user(user: UserCreate, db: db_dependency):
    try:
        new_user = create_user(db=db, user=user)
        return {"message": "User registered successfully", "user_id": new_user.id}
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))


@router.post('/login/')
def login_for_access_token(user: BasicUserInfoForLogin, db: db_dependency):
    if not user.username or not user.password:
        raise HTTPException(status_code=400, detail="Username and password are required.")
    
    user_data = authenticate_user(db, user.username, user.password)
    if user_data:
        access_token = create_access_token(user_data=user_data) 
        refresh_token = create_refresh_token(data={"sub": user_data.username, "id": user_data.id})
        response = JSONResponse({"accessToken": access_token, "refreshToken": refresh_token }, status_code=200)
        response.set_cookie(key="refreshToken", value=refresh_token, httponly=True, secure=True)
        return response
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    
@router.post('/refresh_token')
def refresh_access_token(refresh_token: str, db:db_dependency):
    try:
        decoded_token = verify_refresh_token(refresh_token)
        
        user = db.query(User).filter(User.id == decoded_token['id']).first()
        if not user:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User Not found")
        new_access_token = create_access_token(user_data=user)
        new_refresh_token = create_refresh_token(data={"sub": user.username, "id": user.id})

        response = JSONResponse(
            {"accessToken": new_access_token, "refreshToken": new_refresh_token}, 
            status_code=status.HTTP_200_OK
        )
        response.set_cookie(key="refreshToken", value=new_refresh_token, httponly=True, secure=True)
        return response
    
       
    except Exception as e:
        raise HTTPException(status_code=403, detail="Invalid or expired refresh token")

@router.get('/users/', response_model=List[RetriveUsersModel])
async def get_all_users(current_user: auth_dependency , db: db_dependency):
    users = db.query(User).all()
    if not users:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND)
    return users


@router.delete('/users/{user_id}/', status_code=status.HTTP_204_NO_CONTENT)
def delete_a_specific_user(current_user: auth_dependency, db: db_dependency, user_id: int):
    user_to_delete = db.query(User).filter(User.id == user_id).first()
    if not user_to_delete:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    db.delete(user_to_delete)
    db.commit()
    return {"message": "User deleted successfully"}


@router.put('/users/{user_id}/', status_code=status.HTTP_204_NO_CONTENT)
def update_a_specific_user(current_user: auth_dependency, db: db_dependency, user_id: int, user_update: UpdateUserModel):
    user_to_update = db.query(User).filter(User.id == user_id).first()
    if not user_to_update:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")
    
    for field, value in user_update.dict(exclude_unset=True).items():
        setattr(user_to_update, field, value)
    db.commit()
    return {"message": "User updated successfully"}