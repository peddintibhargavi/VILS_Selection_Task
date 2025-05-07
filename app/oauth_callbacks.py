from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from fastapi.responses import RedirectResponse
import httpx
import jwt
from datetime import datetime, timedelta
from passlib.context import CryptContext
from config_and_models import settings, User, Token, AuthProvider
from db import get_database
import secrets
from typing import Dict, Optional
from bson.objectid import ObjectId

router = APIRouter()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Store to save state and code verifier values temporarily
state_store: Dict[str, str] = {}

# Secret key for JWT token generation
SECRET_KEY = settings.JWT_SECRET_KEY

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Function to create access token
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# Function to get user from database
async def get_user_by_email(email: str):
    db = get_database()
    user = await db["users"].find_one({"email": email})
    return user

async def create_user(user_data: dict):
    db = get_database()
    existing_user = await db["users"].find_one({"email": user_data["email"]})

    provider_entry = {
        "provider": user_data["providers"][0]["provider"],
        "provider_user_id": user_data["providers"][0]["provider_user_id"],
        "connected_at": user_data["providers"][0]["connected_at"]
    }

    if existing_user:
        # Check if provider is already linked
        current_providers = existing_user.get("providers", [])
        if not any(p["provider"] == provider_entry["provider"] for p in current_providers):
            current_providers.append(provider_entry)
            await db["users"].update_one(
                {"email": user_data["email"]},
                {"$set": {"providers": current_providers}}
            )
        
        # Update user profile information if it's more complete than what we already have
        update_data = {}
        if not existing_user.get("first_name") and user_data.get("first_name"):
            update_data["first_name"] = user_data["first_name"]
        if not existing_user.get("last_name") and user_data.get("last_name"):
            update_data["last_name"] = user_data["last_name"]
        if not existing_user.get("full_name") and user_data.get("full_name"):
            update_data["full_name"] = user_data["full_name"]
        if not existing_user.get("profile_picture") and user_data.get("profile_picture"):
            update_data["profile_picture"] = user_data["profile_picture"]
        
        if update_data:
            await db["users"].update_one(
                {"email": user_data["email"]},
                {"$set": update_data}
            )
            
        return await db["users"].find_one({"email": user_data["email"]})
    else:
        # Create a new user with the providers list
        result = await db["users"].insert_one(user_data)
        return await db["users"].find_one({"_id": result.inserted_id})




@router.get("/auth/google/callback")
async def google_callback(request: Request, code: str, state: str):
    """
    Google OAuth2 callback:
    - Validates state to prevent CSRF
    - Exchanges code for access token using PKCE
    - Fetches user info from Google
    - Stores user in database (creates or updates)
    - Issues JWT and redirects to frontend
    """
    if state not in state_store:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    # Exchange code for access token
    token_url = "https://oauth2.googleapis.com/token"
    token_data = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "client_secret": settings.GOOGLE_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "code_verifier": settings.GOOGLE_CODE_VERIFIER
    }

    async with httpx.AsyncClient() as client:
        try:
            token_response = await client.post(token_url, data=token_data)
            token_response.raise_for_status()
            token_info = token_response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to exchange code for token: {str(e)}"
            )

        # Get user info from Google
        user_info_url = "https://www.googleapis.com/oauth2/v2/userinfo"
        headers = {"Authorization": f"Bearer {token_info['access_token']}"}

        try:
            user_response = await client.get(user_info_url, headers=headers)
            user_response.raise_for_status()
            user_info = user_response.json()
        except httpx.HTTPStatusError as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to fetch user info: {str(e)}"
            )

    # Parse full name into first and last name
    first_name = None
    last_name = None
    if user_info.get("name"):
        name_parts = user_info.get("name", "").split(" ", 1)
        first_name = name_parts[0]
        last_name = name_parts[1] if len(name_parts) > 1 else None

    # Prepare user data with enhanced profile information
    user_data = {
        "email": user_info["email"],
        "username": user_info["email"].split("@")[0],
        "first_name": first_name,
        "last_name": last_name,
        "full_name": user_info.get("name"),
        "profile_picture": user_info.get("picture"),
        "hashed_password": pwd_context.hash(secrets.token_urlsafe(16)),
        "is_active": True,
        "role": "user",
        "providers": [
            {
                "provider": "google",
                "provider_user_id": user_info["id"],
                "connected_at": datetime.utcnow().isoformat()
            }
        ]
    }

    # Create or update user
    try:
        user = await create_or_update_user(user_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create or update user: {str(e)}"
        )

    # Create JWT token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["email"]}, expires_delta=access_token_expires
    )

    # Clean up state store
    state_store.pop(state, None)
    
    # Redirect to frontend with token
    return RedirectResponse(url=f"/login-success?token={access_token}")


@router.get("/auth/github/callback")
async def github_callback(request: Request, code: str, state: str):
    """
    GitHub OAuth2 callback:
    - Validates state
    - Exchanges code for access token
    - Fetches user info from GitHub
    - Stores user in database with provider info
    - Issues JWT and redirects to frontend
    """
    if state not in state_store:
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    token_url = "https://github.com/login/oauth/access_token"
    token_data = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "client_secret": settings.GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": settings.GITHUB_REDIRECT_URI,
        "state": state
    }
    headers = {"Accept": "application/json"}

    async with httpx.AsyncClient() as client:
        token_response = await client.post(token_url, data=token_data, headers=headers)
        token_response.raise_for_status()
        token_info = token_response.json()

        # Get basic user info
        user_info_url = "https://api.github.com/user"
        headers = {"Authorization": f"token {token_info['access_token']}"}
        user_response = await client.get(user_info_url, headers=headers)
        user_response.raise_for_status()
        user_info = user_response.json()

        # Get user's primary email
        emails_response = await client.get("https://api.github.com/user/emails", headers=headers)
        emails_response.raise_for_status()
        emails = emails_response.json()
        primary_email = next((e["email"] for e in emails if e["primary"]), None) or emails[0]["email"]

    user_data = {
        "email": primary_email,
        "username": user_info["login"],
        "full_name": user_info.get("name"),
        "hashed_password": pwd_context.hash(secrets.token_urlsafe(16)),
        "is_active": True,
        "role": "user",
        "providers": [
            {
                "provider": "github",
                "provider_user_id": str(user_info["id"]),
                "connected_at": datetime.utcnow().isoformat()
            }
        ]
    }

    user = await create_user(user_data)

    access_token = create_access_token(
        data={"sub": user["email"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    state_store.pop(state, None)
    return RedirectResponse(url=f"/login-success?token={access_token}")

@router.get("/auth/microsoft/callback")
async def microsoft_callback(request: Request, code: str, state: str):
    """
    Microsoft OAuth2 callback:
    - Validates state
    - Exchanges code for access token using PKCE
    - Gets user info from Microsoft Graph
    - Stores user and provider info
    - Issues JWT and redirects
    """
    if state not in state_store:
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    token_url = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
    token_data = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "client_secret": settings.MICROSOFT_CLIENT_SECRET,
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
        "code_verifier": settings.MICROSOFT_CODE_VERIFIER
    }

    async with httpx.AsyncClient() as client:
        token_response = await client.post(token_url, data=token_data)
        token_response.raise_for_status()
        token_info = token_response.json()

        user_info_url = "https://graph.microsoft.com/v1.0/me"
        headers = {"Authorization": f"Bearer {token_info['access_token']}"}
        user_response = await client.get(user_info_url, headers=headers)
        user_response.raise_for_status()
        user_info = user_response.json()

    user_data = {
        "email": user_info["userPrincipalName"],
        "username": user_info["userPrincipalName"].split("@")[0],
        "full_name": user_info.get("displayName"),
        "hashed_password": pwd_context.hash(secrets.token_urlsafe(16)),
        "is_active": True,
        "role": "user",
        "providers": [
            {
                "provider": "microsoft",
                "provider_user_id": user_info["id"],
                "connected_at": datetime.utcnow().isoformat()
            }
        ]
    }

    user = await create_user(user_data)

    access_token = create_access_token(
        data={"sub": user["email"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    state_store.pop(state, None)
    return RedirectResponse(url=f"/login-success?token={access_token}")

@router.get("/auth/facebook/callback")
async def facebook_callback(request: Request, code: str, state: str):
    """
    Facebook OAuth2 callback:
    - Validates state
    - Exchanges code for access token
    - Gets user info from Facebook Graph API
    - Stores user and provider
    - Issues JWT and redirects
    """
    if state not in state_store:
        raise HTTPException(status_code=400, detail="Invalid state parameter")

    token_url = "https://graph.facebook.com/v13.0/oauth/access_token"
    token_data = {
        "client_id": settings.FACEBOOK_CLIENT_ID,
        "client_secret": settings.FACEBOOK_CLIENT_SECRET,
        "code": code,
        "redirect_uri": settings.FACEBOOK_REDIRECT_URI
    }

    async with httpx.AsyncClient() as client:
        token_response = await client.get(token_url, params=token_data)
        token_response.raise_for_status()
        token_info = token_response.json()

        user_info_url = "https://graph.facebook.com/me"
        params = {
            "fields": "id,name,email",
            "access_token": token_info["access_token"]
        }
        user_response = await client.get(user_info_url, params=params)
        user_response.raise_for_status()
        user_info = user_response.json()

    user_email = user_info.get("email", f"{user_info['id']}@facebook.com")
    user_data = {
        "email": user_email,
        "username": f"fb_{user_info['id']}",
        "full_name": user_info.get("name"),
        "hashed_password": pwd_context.hash(secrets.token_urlsafe(16)),
        "is_active": True,
        "role": "user",
        "providers": [
            {
                "provider": "facebook",
                "provider_user_id": user_info["id"],
                "connected_at": datetime.utcnow().isoformat()
            }
        ]
    }

    user = await create_user(user_data)

    access_token = create_access_token(
        data={"sub": user["email"]},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    state_store.pop(state, None)
    return RedirectResponse(url=f"/login-success?token={access_token}")


# Endpoint to verify JWT token and get current user - FIXED VERSION
@router.get("/auth/me")
async def get_current_user(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    
    db = get_database()
    user_doc = await db["users"].find_one({"email": email})
    if user_doc is None:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Convert MongoDB document to Pydantic model to handle ObjectId serialization
    # First, convert ObjectId to string
    if "_id" in user_doc and isinstance(user_doc["_id"], ObjectId):
        user_doc["_id"] = str(user_doc["_id"])
    
    # Create providers list with proper objects
    providers_list = []
    for provider in user_doc.get("providers", []):
        providers_list.append(AuthProvider(**provider))
    
    # Create Pydantic User model
    user = User(
        _id=user_doc["_id"],
        email=user_doc["email"],
        username=user_doc["username"],
        full_name=user_doc.get("full_name"),
        hashed_password=user_doc.get("hashed_password"),
        is_active=user_doc.get("is_active", True),
        role=user_doc.get("role", "user"),
        providers=providers_list
    )
    
    return user

@router.get("/auth/methods")
async def list_auth_methods(token: str = Depends(oauth2_scheme)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

    db = get_database()
    user_doc = await db["users"].find_one({"email": email})
    if user_doc is None:
        raise HTTPException(status_code=404, detail="User not found")

    # Extract only the necessary provider information for the response
    providers = []
    for provider in user_doc.get("providers", []):
        providers.append({
            "provider": provider["provider"],
            "provider_user_id": provider["provider_user_id"],
            "connected_at": provider.get("connected_at")
        })

    return {"email": user_doc["email"], "providers": providers}
async def create_or_update_user(user_data: dict):
    """
    Create a new user or update an existing one with provider information.
    Also updates user profile data if the new information is more complete.
    """
    db = get_database()
    existing_user = await db["users"].find_one({"email": user_data["email"]})

    provider_entry = {
        "provider": user_data["providers"][0]["provider"],
        "provider_user_id": user_data["providers"][0]["provider_user_id"],
        "connected_at": user_data["providers"][0]["connected_at"]
    }

    if existing_user:
        # Check if provider is already linked
        current_providers = existing_user.get("providers", [])
        provider_exists = any(p["provider"] == provider_entry["provider"] for p in current_providers)
        
        # Update operations to perform
        updates = {}
        
        # Add provider if it doesn't exist
        if not provider_exists:
            current_providers.append(provider_entry)
            updates["providers"] = current_providers
        
        # Update user profile information if new data is available
        # This allows us to get more complete profiles over time
        if not existing_user.get("first_name") and user_data.get("first_name"):
            updates["first_name"] = user_data["first_name"]
        
        if not existing_user.get("last_name") and user_data.get("last_name"):
            updates["last_name"] = user_data["last_name"]
            
        if not existing_user.get("full_name") and user_data.get("full_name"):
            updates["full_name"] = user_data["full_name"]
            
        if not existing_user.get("profile_picture") and user_data.get("profile_picture"):
            updates["profile_picture"] = user_data["profile_picture"]
        
        # Perform update if we have changes
        if updates:
            await db["users"].update_one(
                {"email": user_data["email"]},
                {"$set": updates}
            )
        
        return await db["users"].find_one({"email": user_data["email"]})
    else:
        # Create a new user with all the provided data
        result = await db["users"].insert_one(user_data)
        return await db["users"].find_one({"_id": result.inserted_id})