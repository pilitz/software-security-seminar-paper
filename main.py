import json
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from datetime import timedelta
from fastapi import Request
from authlib.integrations.starlette_client import OAuth
from helper import authenticate_user, create_access_token, get_current_user
from starlette.config import Config
from starlette.middleware.sessions import SessionMiddleware
import os
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

SECRET_KEY = os.getenv("SECRET_KEY")
ALGORITHM = os.getenv("ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", 30)

backend = FastAPI()
backend.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)
limiter = Limiter(key_func=get_remote_address)
backend.state.limiter = limiter
backend.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

with open("db.json", "r", encoding="utf-8") as f:
    fake_users_db = json.load(f)


@backend.post("/logout")
async def logout(current_user: dict = Depends(get_current_user)):
    username = current_user["username"]
    # Invalidate current token by removing jti
    fake_users_db[username]["jti"] = None
    return {"message": f"User {username} logged out successfully. Token invalidated."}

@backend.post("/token")
@limiter.limit(os.getenv("RATE_LIMIT", "10/minute"))
async def login_token(request: Request,form_data: OAuth2PasswordRequestForm = Depends()):
    user = authenticate_user(fake_users_db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=int(ACCESS_TOKEN_EXPIRE_MINUTES))
    access_token = create_access_token(
        data={"sub": user['username'], "role": user['role']}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@backend.get("/protected")
async def read_protected(current_user: dict = Depends(get_current_user)):
    return {"message": f"Hello {current_user['username']}, your role is {current_user['role']}"}

@backend.get("/admin")
async def read_admin(current_user: dict = Depends(get_current_user)):
    if current_user['role'] != 'admin':
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return {"message": f"Welcome admin {current_user['username']}!"}
config = Config('.env')

# OAuth setup
oauth = OAuth(config)
oauth.register(
    name='google',
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={'scope': 'openid email profile','response_type': 'code'},
)

@backend.get('/login')
@limiter.limit(os.getenv("RATE_LIMIT", "5/minute"))
async def login(request: Request):
    redirect_uri = request.url_for('auth')  # this must match the registered redirect URI
    return await oauth.google.authorize_redirect(request, redirect_uri)

@backend.get('/auth')
async def auth(request: Request):
    token = await oauth.google.authorize_access_token(request)
    user_info = token['userinfo']
    username = user_info['email']

    # Benutzer in fake_users_db registrieren, falls nicht vorhanden
    if username not in fake_users_db:
        fake_users_db[username] = {
            "username": username,
            "hashed_password": None,
            "role": "user",
            "jti": None 
        }
        

    # Zugriffstoken generieren inkl. jti
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username, "role": fake_users_db[username]['role']},
        expires_delta=access_token_expires
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": user_info
    }

