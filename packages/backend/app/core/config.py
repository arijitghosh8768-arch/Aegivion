from pydantic_settings import BaseSettings
import os

class Settings(BaseSettings):
    PORT: int = 8000
    DATABASE_URL: str = "mongodb://localhost:27017/aegivion"
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Security Configuration
    SECRET_KEY: str = os.getenv("SECRET_KEY", "development-secret-key")
    JWT_ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS settings
    CORS_ORIGINS: list = [
        "http://localhost:3000",
        "http://localhost:8000"
    ]

settings = Settings()
