import httpx
import secrets
from urllib.parse import urlencode
from fastapi.responses import RedirectResponse
from fastapi import HTTPException, status
from config_and_models import settings
from oauth_callbacks import state_store

# Google OAuth2 with PKCE
async def google_oauth2():
    """
    Initiate Google OAuth2 flow with PKCE
    - Generates a state parameter for CSRF protection
    - Uses PKCE for added security
    - Redirects the user to Google's authorization page
    """
    google_auth_url = "https://accounts.google.com/o/oauth2/v2/auth"
    state = secrets.token_urlsafe(16)
    # Store state for validation during callback
    state_store[state] = "google"
    
    params = {
        "client_id": settings.GOOGLE_CLIENT_ID,
        "redirect_uri": settings.GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "code_challenge": settings.GOOGLE_CODE_CHALLENGE,
        "code_challenge_method": "S256",
        "prompt": "select_account consent",  # Force consent screen to appear
        "access_type": "offline"  # Request refresh token
    }
    return RedirectResponse(f"{google_auth_url}?{urlencode(params)}")

# GitHub OAuth2
async def github_oauth2():
    """
    Initiate GitHub OAuth2 flow
    - Generates a state parameter for CSRF protection
    - Redirects the user to GitHub's authorization page
    """
    github_auth_url = "https://github.com/login/oauth/authorize"
    state = secrets.token_urlsafe(16)
    # Store state for validation during callback
    state_store[state] = "github"
    
    params = {
        "client_id": settings.GITHUB_CLIENT_ID,
        "redirect_uri": settings.GITHUB_REDIRECT_URI,
        "scope": "read:user user:email",
        "state": state
    }
    return RedirectResponse(f"{github_auth_url}?{urlencode(params)}")

# Microsoft OAuth2 with PKCE
async def microsoft_oauth2():
    """
    Initiate Microsoft OAuth2 flow with PKCE
    - Generates a state parameter for CSRF protection
    - Uses PKCE for added security
    - Redirects the user to Microsoft's authorization page
    """
    microsoft_auth_url = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    state = secrets.token_urlsafe(16)
    # Store state for validation during callback
    state_store[state] = "microsoft"
    
    params = {
        "client_id": settings.MICROSOFT_CLIENT_ID,
        "redirect_uri": settings.MICROSOFT_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid profile email",
        "state": state,
        "code_challenge": settings.MICROSOFT_CODE_CHALLENGE,
        "code_challenge_method": "S256",
        "prompt": "select_account"  # Force account selection
    }
    return RedirectResponse(f"{microsoft_auth_url}?{urlencode(params)}")

# Facebook OAuth2
async def facebook_oauth2():
    """
    Initiate Facebook OAuth2 flow
    - Generates a state parameter for CSRF protection
    - Redirects the user to Facebook's authorization page
    """
    facebook_auth_url = "https://www.facebook.com/v13.0/dialog/oauth"
    state = secrets.token_urlsafe(16)
    # Store state for validation during callback
    state_store[state] = "facebook"
    
    params = {
        "client_id": settings.FACEBOOK_CLIENT_ID,
        "redirect_uri": settings.FACEBOOK_REDIRECT_URI,
        "scope": "email",
        "state": state,
        "auth_type": "rerequest"  # Force permission dialog
    }
    return RedirectResponse(f"{facebook_auth_url}?{urlencode(params)}")