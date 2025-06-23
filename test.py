import time
import os
import pytest
import requests
from jose import jwt

BASE_URL = "http://localhost:8080"
headers = {"Content-Type": "application/x-www-form-urlencoded"}
SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key")

test_users = {
    "user": {"username": "alice", "password": "secret"},
    "admin": {"username": "admin", "password": "adminpass"},
    "invalid": {"username": "wrong", "password": "wrong"},
}

@pytest.fixture
def user_token():
    res = requests.post(f"{BASE_URL}/token", data=test_users["user"], headers=headers)
    assert res.status_code == 200
    return res.json()["access_token"]

@pytest.fixture
def admin_token():
    res = requests.post(f"{BASE_URL}/token", data=test_users["admin"], headers=headers)
    assert res.status_code == 200
    return res.json()["access_token"]

def test_invalid_login():
    res = requests.post(f"{BASE_URL}/token", data=test_users["invalid"], headers=headers)
    assert res.status_code == 401

def test_protected_route(user_token):
    res = requests.get(f"{BASE_URL}/protected", headers={"Authorization": f"Bearer {user_token}"})
    assert res.status_code == 200

def test_admin_access_forbidden(user_token):
    res = requests.get(f"{BASE_URL}/admin", headers={"Authorization": f"Bearer {user_token}"})
    assert res.status_code == 403

def test_admin_access_allowed(admin_token):
    res = requests.get(f"{BASE_URL}/admin", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200

def test_token_tampering(user_token):
    decoded = jwt.decode(user_token, key=None, options={"verify_signature": False})
    decoded["role"] = "admin"
    tampered = jwt.encode(decoded, "fake-secret", algorithm="HS256")
    res = requests.get(f"{BASE_URL}/protected", headers={"Authorization": f"Bearer {tampered}"})
    assert res.status_code == 401

def test_expired_token():
    token = jwt.encode(
        {"sub": "alice", "role": "user", "exp": time.time() + 2, "jti": "manual-jti"},
        SECRET_KEY,
        algorithm="HS256",
    )
    res = requests.get(f"{BASE_URL}/protected", headers={"Authorization": f"Bearer {token}"})
    assert res.status_code in (200, 401)  # Token könnte schon abgelaufen sein
    time.sleep(3)
    res2 = requests.get(f"{BASE_URL}/protected", headers={"Authorization": f"Bearer {token}"})
    assert res2.status_code == 401