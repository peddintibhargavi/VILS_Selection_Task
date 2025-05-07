from pydantic import BaseModel, Field, EmailStr
from pydantic_settings import BaseSettings
from typing import Optional, List
from bson import ObjectId
from pydantic_core import core_schema

# --- Custom PyObjectId for Pydantic v2 ---
class PyObjectId(str):
    @classmethod
    def __get_pydantic_core_schema__(cls, _source_type, _handler):
        return core_schema.no_info_after_validator_function(
            cls.validate,
            core_schema.str_schema(),
            serialization=core_schema.to_string_ser_schema(),
        )

    @classmethod
    def validate(cls, v):
        # Accept ObjectId or string, convert to string if valid
        if isinstance(v, ObjectId):
            return str(v)
        if isinstance(v, str) and ObjectId.is_valid(v):
            return v
        raise ValueError("Invalid ObjectId")

# --- Settings ---
class Settings(BaseSettings):
    JWT_SECRET_KEY: str
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    GOOGLE_CLIENT_ID: str
    GOOGLE_CLIENT_SECRET: str
    GOOGLE_REDIRECT_URI: str
    GOOGLE_CODE_VERIFIER: str
    GOOGLE_CODE_CHALLENGE: str

    GITHUB_CLIENT_ID: str
    GITHUB_CLIENT_SECRET: str
    GITHUB_REDIRECT_URI: str
    GITHUB_CODE_VERIFIER: str
    GITHUB_CODE_CHALLENGE: str

    MICROSOFT_CLIENT_ID: str
    MICROSOFT_CLIENT_SECRET: str
    MICROSOFT_REDIRECT_URI: str
    MICROSOFT_CODE_VERIFIER: str
    MICROSOFT_CODE_CHALLENGE: str

    FACEBOOK_CLIENT_ID: str
    FACEBOOK_CLIENT_SECRET: str
    FACEBOOK_REDIRECT_URI: str
    FACEBOOK_CODE_VERIFIER: str
    FACEBOOK_CODE_CHALLENGE: str

    MONGO_URI: str
    DB_NAME: str = "auth_system"

    class Config:
        env_file = ".env"

settings = Settings()

# --- Token Model ---
class Token(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"

    model_config = dict(from_attributes=True)

# --- AuthProvider Model ---
class AuthProvider(BaseModel):
    provider: str
    provider_user_id: str
    connected_at: Optional[str] = None

# --- User Model ---
class User(BaseModel):
    id: PyObjectId = Field(default_factory=PyObjectId, alias="_id")
    email: EmailStr
    username: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    full_name: Optional[str] = None
    profile_picture: Optional[str] = None
    hashed_password: Optional[str] = None
    is_active: bool = True
    role: str = "user"
    providers: List[AuthProvider] = []

    model_config = dict(
        populate_by_name=True,
        json_encoders={ObjectId: str},
    )