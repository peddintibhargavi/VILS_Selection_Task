from fastapi import APIRouter, Request, Response, HTTPException, Depends
from fastapi.responses import RedirectResponse
import os
from pathlib import Path

# Create router for frontend routes
router = APIRouter()

# Redirect to frontend with token
@router.get("/login-success")
async def login_success(token: str):
    """
    Handle successful OAuth login by redirecting to frontend
    with the token as a query parameter
    """
    # Replace this URL with your actual frontend URL
    frontend_url = "http://localhost:3000/auth-callback"
    
    # Redirect to the frontend with the token
    return RedirectResponse(url=f"{frontend_url}?token={token}")