from fastapi.testclient import TestClient
from app.main import app
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.db.base import  get_db, Base
from sqlalchemy.pool import StaticPool
from app.auth.auth import create_refresh_token
from app.db.models import User
from app.utils.dependencies import get_current_user
from app.utils.security import hash_password

DATABASE_URL = "sqlite:///:memory:"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False}, poolclass=StaticPool)
TestSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base.metadata.create_all(bind=engine)

def override_get_db():
    db = TestSessionLocal()
    try:
        yield db
    finally:
        db.close()


def override_get_current_user():
    return User(
        id=1, 
        username="adminuser", 
        email="admin@example.com", 
        phone_number="1234567890", 
        role="admin",
        password=hash_password("AdminPass123!")
    )

def override_get_current_non_admin_user():
    return User(
        id=2, 
        username="regularuser", 
        email="regular@example.com", 
        phone_number="0987654321", 
        role="user",
        password=hash_password("RegularPass123!")
    )


def setup_test_users():
    """
    Helper function to set up test users in the database
    """
    db = TestSessionLocal()
    
    # Clear existing users
    db.query(User).delete()
    
    # Create test users with hashed passwords
    test_users = [
        User(
            username="user1", 
            email="user1@example.com", 
            phone_number="1111111111", 
            role="user",
            password=hash_password("User1Pass123!")
        ),
        User(
            username="user2", 
            email="user2@example.com", 
            phone_number="2222222222", 
            role="user",
            password=hash_password("User2Pass123!")
        ),
        User(
            username="user3", 
            email="user3@example.com", 
            phone_number="3333333333", 
            role="user",
            password=hash_password("User3Pass123!")
        )
    ]
    
    for user in test_users:
        db.add(user)
    
    db.commit()
    
    # Refresh the users to get their IDs
    db.refresh(test_users[0])
    db.refresh(test_users[1])
    db.refresh(test_users[2])
    
    # Return the IDs of created users for reference
    return [user.id for user in test_users]


app.dependency_overrides[get_db] = override_get_db
app.dependency_overrides[get_current_user] = override_get_current_user

client = TestClient(app)




################################################################################################
"""  TESTING  REGISTERATION APIS (POST /api/users/) """
################################################################################################

def test_register_user_success():
    """
    Test successful user registration
    """
    user_data = {
        "username": "asifxohd",
        "email": "asifxohd@gmail.com",
        "password": "Asif@123",
        "phone_number": "9876543210",
        "role": "user"
    }
    
    response = client.post("/api/users/", json=user_data)
    
    assert response.status_code == 201
    assert "user_id" in response.json()
    assert response.json()["message"] == "User registered successfully"

def test_register_user_duplicate_username():
    """
    Test registration with an existing username (should fail)
    """
    first_user_data = {
        "username": "asifxohd",
        "email": "asifxohd@gmail.com",
        "password": "Asif@123",
        "phone_number": "9876543210",
        "role": "user"
    }
    client.post("/api/users/", json=first_user_data)
    
    duplicate_user_data = {
        "username": "asifxohd",
        "email": "asifxohd@gmail.com",
        "password": "Asif@123",
        "phone_number": "9876543210",
        "role": "user"
    }
    
    response = client.post("/api/users/", json=duplicate_user_data)
    
    assert response.status_code == 401
    assert "already exists" in response.json()["detail"].lower()

def test_register_user_invalid_data():
    """
    Test registration with invalid data
    """
    
    invalid_user_data = {
        "username": "", 
        "email": "invalid-email",
        "password": "short"
    }
    
    response = client.post("/api/users/", json=invalid_user_data)
    assert response.status_code == 422

def register_test_user():
    user_data = {
        "username": "asifxohd",
        "email": "asifxohd@gmail.com",
        "password": "Asif@123",
        "phone_number": "9876543210",
        "role": "user"
    }
    client.post("/api/users/", json=user_data)


################################################################################################
"""  TESTING  LOGIN API (POST /api/login/) """
################################################################################################

def test_login_success():
    """
    Test login with valid credentials
    """
    register_test_user()  

    login_data = {
        "username": "asifxohd",
        "password": "Asif@123"
    }
    response = client.post("/api/login/", json=login_data)

    assert response.status_code == 200
    assert "accessToken" in response.json()
    assert "refreshToken" in response.json()
    assert response.cookies.get("refreshToken") is not None

# 2. Test login with missing credentials
def test_login_missing_credentials():
    """
    Test login with missing username or password
    """
    login_data = {
        "username": "",  
        "password": ""
    }
    response = client.post("/api/login/", json=login_data)

    assert response.status_code == 400
    assert response.json()["detail"] == "Username and password are required."

def test_login_invalid_credentials():
    """
    Test login with invalid credentials
    """
    register_test_user()  

    login_data = {
        "username": "wrong_username",
        "password": "wrong_password"
    }
    response = client.post("/api/login/", json=login_data)

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid credentials"


################################################################################################
"""  TESTING Refresh Token API (POST /api/refresh_token/) """
################################################################################################

# Helper function to register a user and get their refresh token
def register_test_user():
    user_data = {
        "username": "asifxohd",
        "email": "asifxohd@gmail.com",
        "password": "Asif@123",
        "phone_number": "9876543210",
        "role": "user"
    }
    client.post("/api/users/", json=user_data)
    login_data = {
        "username": "asifxohd",
        "password": "Asif@123"
    }
    response = client.post("/api/login/", json=login_data)
    return response.cookies.get("refreshToken")

# 1. Test successful refresh token generation
def test_refresh_token_success():
    """
    Test refreshing tokens with a valid refresh token
    """
    refresh_token = register_test_user()  

    response = client.post(f"/api/refresh_token?refresh_token={refresh_token}")

    assert response.status_code == 200
    assert "accessToken" in response.json()
    assert "refreshToken" in response.json()
    assert response.cookies.get("refreshToken") is not None


def test_refresh_token_invalid_token():
    """
    Test refreshing tokens with an invalid or expired refresh token
    """
    invalid_token = "invalid_or_expired_token"

    response = client.post(f"/api/refresh_token?refresh_token={invalid_token}")

    assert response.status_code == 403
    assert response.json()["detail"] == "Invalid or expired refresh token"


def test_refresh_token_user_not_found():
    """
    Test refreshing token for a non-existent user
    """
    non_existent_token = create_refresh_token(data={"sub": "nonexistent", "id": 100})  
    response = client.post(f"/api/refresh_token?refresh_token={non_existent_token}")
    assert response.status_code == 403
    assert response.json()["detail"] == "Invalid or expired refresh token"



################################################################################################
"""  TESTING GET ALL USERS API (GET /api/users/) """
################################################################################################

def test_get_all_users_success():
    """
    Test successful retrieval of all users
    """
    setup_test_users()
    
    response = client.get("/api/users/")
    
    assert response.status_code == 200
    assert len(response.json()) > 0
    assert all('username' in user for user in response.json())

def test_get_all_users_no_users():
    """
    Test retrieving users when no users exist
    """
    # Clear any existing users
    db = TestSessionLocal()
    db.query(User).delete()
    db.commit()
    
    response = client.get("/api/users/")
    
    assert response.status_code == 404

def test_get_all_users_unauthorized():
    """
    Test unauthorized access to get all users
    """
    app.dependency_overrides[get_current_user] = override_get_current_non_admin_user
    response = client.get("/api/users/")
    app.dependency_overrides[get_current_user] = override_get_current_user
    assert response.status_code == 404

################################################################################################
"""  TESTING DELETE USER API (DELETE /api/users/{user_id}/) """
################################################################################################

def test_delete_user_success():
    """
    Test successful deletion of a specific user
    """
    user_ids = setup_test_users()
    user_to_delete_id = user_ids[0]
    
    response = client.delete(f"/api/users/{user_to_delete_id}/")
    
    assert response.status_code == 204
    
    db = TestSessionLocal()
    deleted_user = db.query(User).filter(User.id == user_to_delete_id).first()
    assert deleted_user is None

def test_delete_nonexistent_user():
    """
    Test deleting a user that does not exist
    """
    non_existent_user_id = 9999
    
    response = client.delete(f"/api/users/{non_existent_user_id}/")
    
    assert response.status_code == 404
    assert response.json()['detail'] == "User not found"

# def test_delete_user_unauthorized():
#     """
#     Test deleting a user by a non-admin user
#     """
#     user_ids = setup_test_users()
#     user_to_delete_id = user_ids[0]    
#     app.dependency_overrides[get_current_user] = override_get_current_non_admin_user
#     response = client.delete(f"/api/users/{user_to_delete_id}/")
#     app.dependency_overrides[get_current_user] = override_get_current_user
#     assert response.status_code == 404

################################################################################################
"""  TESTING UPDATE USER API (PUT /api/users/{user_id}/) """
################################################################################################

def test_update_user_success():
    """
    Test successful update of a specific user
    """
    user_ids = setup_test_users()
    user_to_update_id = user_ids[0]
    
    update_data = {
        "email": "updated_email@example.com",
        "phone_number": "9999999999"
    }
    
    response = client.put(f"/api/users/{user_to_update_id}/", json=update_data)
    
    assert response.status_code == 204
    
    db = TestSessionLocal()
    updated_user = db.query(User).filter(User.id == user_to_update_id).first()
    assert updated_user.email == "updated_email@example.com"
    assert updated_user.phone_number == "9999999999"

def test_update_nonexistent_user():
    """
    Test updating a user that does not exist
    """
    non_existent_user_id = 9999
    
    update_data = {
        "email": "updated_email@example.com",
        "phone_number": "9999999999"
    }
    
    response = client.put(f"/api/users/{non_existent_user_id}/", json=update_data)
    
    assert response.status_code == 404
    assert response.json()['detail'] == "User not found"

# def test_update_user_unauthorized():
#     """
#     Test updating a user by a non-admin user
#     """
#     user_ids = setup_test_users()
#     user_to_update_id = user_ids[0]
    
#     update_data = {
#         "email": "updated_email@example.com",
#         "phone_number": "9999999999"
#     }
    
#     response = client.put(
#         f"/api/users/{user_to_update_id}/?required_role=admin",  
#         json=update_data,
#         headers={"Authorization": "Bearer guiguigiiuguigiygui"}  
#     )
    
#     print(f"Response status code: {response.status_code}")
#     print(f"Response content: {response.content}")

#     assert response.status_code == 401 
