# Seminar Paper: Secure Authentication System with FastAPI

**Author:** Paul Ilitz

This project implements a secure authentication and authorization system using [FastAPI](https://fastapi.tiangolo.com/). It demonstrates best practices for handling user credentials, JWT-based authentication, OAuth2 login with Google, rate limiting, and secure session management.

## Features

- **JWT Authentication:** Secure login with JSON Web Tokens, including token invalidation and jti tracking.
- **Role-based Access Control:** Separate endpoints for users and admins.
- **OAuth2 Login:** Google OAuth2 login integration.
- **Rate Limiting:** Prevent brute-force attacks using configurable rate limits.
- **Password Hashing:** Secure password storage using bcrypt.
- **Logout Endpoint:** Invalidate tokens on logout.
- **Extensive Testing:** Automated tests for authentication, authorization, and token security.

## Requirements

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (recommended for dependency management)

## Installation

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd seminar-paper
   ```

2. **Install dependencies using [uv](https://github.com/astral-sh/uv):**
   ```bash
   uv sync
   ```

3. **Set up environment variables:**
   - Copy `.env` and adjust secrets as needed.
   - Make sure to set `SECRET_KEY`, Google OAuth credentials, and rate limits.

## Usage

### Start the Application

```bash
uv run app.py
```
- Use `-d` or `--development` for development mode (localhost).

### API Endpoints

- `POST /token`: Obtain JWT token (username/password).
- `GET /protected`: Access protected resource (requires valid token).
- `GET /admin`: Admin-only resource (requires admin role).
- `POST /logout`: Invalidate current JWT token.
- `GET /login`: Start Google OAuth2 login.
- `GET /auth`: Google OAuth2 callback.

### Example: Obtain Token

```bash
curl -X POST -d "username=alice&password=secret" http://localhost:8080/token
```

### Example: Access Protected Route

```bash
curl -H "Authorization: Bearer <your_token>" http://localhost:8080/protected
```

## Testing

Run all tests using [pytest](https://docs.pytest.org/):

```bash
uv run pytest test.py
```

## Security Features

- **Password Hashing:** All passwords are hashed with bcrypt.
- **JWT with jti:** Each token has a unique identifier (`jti`) and can be invalidated on logout.
- **Token Expiry:** Tokens expire after a configurable time.
- **Rate Limiting:** Configurable per endpoint to prevent abuse.
- **OAuth2:** Secure third-party login via Google.
- **Session Middleware:** For secure OAuth2 flows.

## Configuration

All configuration is managed via the `.env` file:

- `SECRET_KEY`: Secret for JWT signing.
- `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET`: For Google OAuth2.
- `RATE_LIMIT`: e.g., `5/minute`.
- `ALGORITHM`: JWT algorithm (default: HS256).
- `ACCESS_TOKEN_EXPIRE_MINUTES`: Token lifetime.

## User Database

User data is stored in `db.json` for demonstration purposes. In production, use a real database.

## License

This project is for educational purposes.

## Acknowledgements

- [FastAPI](https://fastapi.tiangolo.com/)
- [Authlib](https://docs.authlib.org/)
- [python-jose](https://python-jose.readthedocs.io/)
- [slowapi](https://slowapi.readthedocs.io/)
