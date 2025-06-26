from passlib.context import CryptContext

# Create a password hashing context using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Hash the password "password123"
hashed = pwd_context.hash("password123")

# Print the hashed password
print(hashed)
