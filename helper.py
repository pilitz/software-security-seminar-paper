import json
import uuid
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
import os
from passlib.context import CryptContext

# Load the database from a JSON file
def get_db():
    with open("db.json", "r", encoding="utf-8") as f:
        db = json.load(f) 
    return db

# Save the database to a JSON file
def set_db(new_db):
    with open("db.json", "w", encoding="utf-8") as f:
        json.dump(new_db, f, ensure_ascii=False, indent=2)

# Load secret key and algorithm from environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)

# Set up password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# Set up OAuth2 password bearer authentication
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Verify a plain password against a hashed password
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

# Retrieve a user from the database by username
def get_user(db, username: str):
    user = db.get(username)
    return user

# Authenticate a user by username and password
def authenticate_user(db, username: str, password: str):
    user = get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user['hashed_password']):
        return False
    return user

# Create a JWT access token for a user
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    # Generate a unique JWT ID (jti)
    jti = str(uuid.uuid4())
    to_encode.update({"jti": jti})
    username = data.get("sub")
    if username:
        # Store the jti in the user's record for token revocation
        db = get_db()
        db[username]["jti"] = jti
        set_db(db)
    # Set token expiration time
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    # Encode and return the JWT token
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

# Dependency to get the current user from the JWT token
async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        # Decode the JWT token
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_jti: str = payload.get("jti")
        if username is None or token_jti is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    # Retrieve user and check if the jti matches (token is valid)
    user = get_user(get_db(), username)
    if user is None or user["jti"] != token_jti:
        raise credentials_exception
    return user