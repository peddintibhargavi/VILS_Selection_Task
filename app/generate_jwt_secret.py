import secrets

secret = secrets.token_urlsafe(32)
print(f"JWT_SECRET_KEY={secret}")
