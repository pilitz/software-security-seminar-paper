import json
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from fastapi import Request
from authlib.integrations.starlette_client import OAuth
from helper import authenticate_user, create_access_token, get_current_user, get_db, set_db
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
import os
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# Load secret key and algorithm from environment variables
SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)

# Load OAuth configuration from .env file
config = Config('.env')

# Initialize FastAPI app
backend = FastAPI()
# Add session middleware for OAuth
backend.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
# Set up rate limiter
limiter = Limiter(key_func=get_remote_address)
backend.state.limiter = limiter
backend.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# Endpoint for logging out a user and invalidating their token
@backend.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    # Invalidate current token by removing jti
    db = get_db()
    db[username]["jti"] = None
    set_db(db)
    return {"message": f"User {username} logged out successfully. Token invalidated."}

# Endpoint for obtaining a JWT token using username and password
@backend.post("/token")
@limiter.limit(os.getenv("RATE_LIMIT", "20/minute"))
async def login_token(request: Request,form_data: OAuth2PasswordRequestForm = Depends()):
    # Authenticate user with username and password
    user = authenticate_user(get_db(), form_data.username, form_data.password)
    if not user:
        # Raise error if authentication fails
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Set token expiration time
    access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    # Create access token for the user
    access_token = create_access_token(
        data={"sub": user['username'], "role": user['role']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# Protected endpoint, requires authentication
@backend.get("/protected")
async def read_protected(current_user: dict = Depends(get_current_user)):
    return {"message": f"Hello {current_user['username']}, your role is {current_user['role']}"}

# Admin-only endpoint, checks user role
@backend.get("/admin")
async def read_admin(current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return {"message": f"Welcome admin {current_user['username']}!"}

# OAuth setup for Google login
oauth = OAuth(config)
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile','response_type': 'code'},
)

# Endpoint to start Google OAuth login flow
@backend.get('/login')
@limiter.limit(os.getenv("RATE_LIMIT", "20/minute"))
async def login(request: Request):
    # Redirect user to Google for authentication
    redirect_uri = request.url_for('auth')  # this must match the registered redirect URI
    return await oauth.google.authorize_redirect(request, redirect_uri)

# OAuth callback endpoint for Google authentication
@backend.get('/auth')
async def auth(request: Request):
    # Get token and user info from Google
    token = await oauth.google.authorize_access_token(request)
    user_info = token['userinfo']
    username = user_info['email']

    db = get_db()
    # Register user in the database if not already present
    if username not in db:
        db[username] = {
            "username": username,
            "hashed_password": None,
            "role": "user",
            "jti": None 
        }
        set_db(db)

    # Generate access token including jti
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username, "role": db[username]['role']},
        expires_delta=access_token_expires
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_info
    }

