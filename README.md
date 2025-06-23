# Seminar Paper: Secure FastAPI Authentication Example

**Author:** Paul Ilitz

This project demonstrates a secure authentication system using FastAPI, JWT tokens, OAuth (Google), and rate limiting. It is designed for educational purposes to showcase best practices in user authentication, token management, and API security.

## Features

- **JWT-based authentication** with token revocation (logout/invalidate)
- **Role-based access control** (user/admin)
- **Google OAuth 2.0 login** integration
- **Rate limiting** to prevent brute-force attacks
- **Password hashing** using bcrypt
- **Replay attack prevention** (tokens are invalidated on logout)
- **Environment-based configuration** via `.env` file

## Requirements

- Python 3.12+
- See `pyproject.toml` for dependencies

## Setup

1. **Clone the repository** and navigate to the project directory.

2. **Install dependencies**:
   ```bash
   uv sync
   ```
   Or use your preferred tool (e.g., `pip install .` if using PEP 517/518).

3. **Configure environment variables**:
   - Copy `.env.example` to `.env` and fill in your secrets, or edit `.env` directly.

4. **Database**:
   - The user database is stored in `db.json`. Default users are provided.

## Running the Application

- **Development mode** (localhost only):
  ```bash
  uv run app.py --development
  ```
- **Production mode** (binds to all interfaces):
  ```bash
  uv run app.py
  ```

The API will be available at `http://localhost:8080`.

## API Endpoints

- `POST /token` — Obtain JWT token with username/password
- `POST /logout` — Invalidate current JWT token
- `GET /protected` — Protected route (requires authentication)
- `GET /admin` — Admin-only route
- `GET /login` — Start Google OAuth login
- `GET /auth` — Google OAuth callback

## Testing

- Run tests with:
  ```bash
  uv run pytest test.py
  ```

## Security Notes

- Passwords are hashed using bcrypt.
- JWT tokens are invalidated on logout (using a unique `jti` per user).
- Rate limiting is enforced on sensitive endpoints.
- OAuth login is supported via Google.

## License

This project is for educational purposes.
