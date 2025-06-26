import os
import pytest
import requests
from jose import jwt

BASE_URL = "http://localhost:8080"
headers = {"Content-Type": "application/x-www-form-urlencoded"}
SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key")

# Test user credentials
test_users = {
    "user": {"username": "alice", "password": "secret"},
    "admin": {"username": "admin", "password": "adminpass"},
    "invalid": {"username": "wrong", "password": "wrong"},
}

# Fixture to get a valid user token
@pytest.fixture
def user_token():
    res = requests.post(f"{BASE_URL}/token", data=test_users["user"], headers=headers)
    assert res.status_code == 200
    return res.json()["access_token"]

# Fixture to get a valid admin token
@pytest.fixture
def admin_token():
    res = requests.post(f"{BASE_URL}/token", data=test_users["admin"], headers=headers)
    assert res.status_code == 200
    return res.json()["access_token"]

# Test invalid login credentials
def test_invalid_login():
    res = requests.post(f"{BASE_URL}/token", data=test_users["invalid"], headers=headers)
    assert res.status_code == 401

# Test access to protected route with valid user token
def test_protected_route(user_token):
    res = requests.get(f"{BASE_URL}/protected", headers={"Authorization": f"Bearer {user_token}"})
    assert res.status_code == 200
    requests.post(f"{BASE_URL}/logout",headers={"Authorization": f"Bearer {user_token}"})

# Test that normal user cannot access admin route
def test_admin_access_forbidden(user_token):
    res = requests.get(f"{BASE_URL}/admin", headers={"Authorization": f"Bearer {user_token}"})
    assert res.status_code == 403
    requests.post(f"{BASE_URL}/logout",headers={"Authorization": f"Bearer {user_token}"})

# Test that admin can access admin route
def test_admin_access_allowed(admin_token):
    res = requests.get(f"{BASE_URL}/admin", headers={"Authorization": f"Bearer {admin_token}"})
    assert res.status_code == 200
    requests.post(f"{BASE_URL}/logout",headers={"Authorization": f"Bearer {admin_token}"})

# Test that tampering with the token results in unauthorized access
def test_token_tampering(user_token):
    decoded = jwt.decode(user_token, key=None, options={"verify_signature": False})
    decoded["role"] = "admin"
    tampered = jwt.encode(decoded, "fake-secret", algorithm="HS256")
    res = requests.get(f"{BASE_URL}/protected", headers={"Authorization": f"Bearer {tampered}"})
    assert res.status_code == 401
    requests.post(f"{BASE_URL}/logout",headers={"Authorization": f"Bearer {user_token}"})

# Test that a token cannot be reused after logout (replay attack prevention)
def test_replay_token_fails_after_logout(user_token):
    # Perform logout
    res = requests.post(f"{BASE_URL}/logout", headers={"Authorization": f"Bearer {user_token}"})
    assert res.status_code in (200, 204)
    # Try to use the same token again
    res2 = requests.get(f"{BASE_URL}/protected", headers={"Authorization": f"Bearer {user_token}"})
    assert res2.status_code == 401

# Test that rate limiting is enforced on the token endpoint
def test_rate_limit_on_token():
    max_attempts = 60 
    hit_rate_limit = False
    for i in range(max_attempts):
        res = requests.post(f"{BASE_URL}/token", data=test_users["user"], headers=headers)
        if res.status_code == 429:
            hit_rate_limit = True
            break
    assert hit_rate_limit, "Rate limit was not enforced after many requests"
    # Attempt logout to clean up (may fail if rate limit hit)
    requests.post(f"{BASE_URL}/logout",headers={"Authorization": f"Bearer {user_token}"})