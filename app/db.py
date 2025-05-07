from motor.motor_asyncio import AsyncIOMotorClient
from config_and_models import settings

client = None
db = None

def get_database():
    global client, db
    if client is None:
        client = AsyncIOMotorClient(settings.MONGO_URI)
        db = client[settings.DB_NAME]
        print(f"Connected to MongoDB: {settings.DB_NAME}")
    return db
