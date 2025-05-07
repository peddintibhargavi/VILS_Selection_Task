from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from config_and_models import settings
from db import get_database

from oauth import google_oauth2, github_oauth2, microsoft_oauth2, facebook_oauth2
from oauth_callbacks import router as callbacks_router
from frontend_routes import router as frontend_router
from jwt_utils import get_current_user

app = FastAPI(title="OAuth2 API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(callbacks_router)
app.include_router(frontend_router)

@app.get("/auth/google/login")
async def google_login():
    return await google_oauth2()

@app.get("/auth/github/login")
async def github_login():
    return await github_oauth2()

@app.get("/auth/microsoft/login")
async def microsoft_login():
    return await microsoft_oauth2()

@app.get("/auth/facebook/login")
async def facebook_login():
    return await facebook_oauth2()

# Add user route for redundancy, in case the one in oauth_callbacks is not being hit
@app.get("/auth/me")
async def get_me(user = Depends(get_current_user)):
    return user

@app.get("/")
async def root():
    return {
        "message": "OAuth2 Authentication API",
        "endpoints": {
            "Google Login": "/auth/google/login",
            "GitHub Login": "/auth/github/login",
            "Microsoft Login": "/auth/microsoft/login",
            "Facebook Login": "/auth/facebook/login",
            "User Profile": "/auth/me",
        }
    }

@app.on_event("startup")
async def startup_db_client():
    app.mongodb_client = AsyncIOMotorClient(settings.MONGO_URI)
    app.mongodb = app.mongodb_client[settings.DB_NAME]
    print(f"Connected to MongoDB: {settings.DB_NAME}")

@app.on_event("shutdown")
async def shutdown_db_client():
    app.mongodb_client.close()
    print("MongoDB connection closed")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)