from pydantic_settings import BaseSettings
from pydantic import field_validator

class Settings(BaseSettings):
    PORT: int = 8000
    DATABASE_URL: str = "postgresql://aegivion_user:aegivion_pass@localhost:5432/aegivion_db"
    REDIS_URL: str = "redis://localhost:6379/0"
    
    # Security Configuration
    SECRET_KEY: str = "super-secret-default-key-32-chars-long"
    JWT_ALGORITHM: str = "RS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # CORS settings
    CORS_ORIGINS: list = [
        "http://localhost:3000",
        "http://localhost:8000"
    ]

    @field_validator('DATABASE_URL')
    def validate_database_url(cls, v: str) -> str:
        if not v.startswith('postgresql://') and not v.startswith('postgresql+psycopg2://'):
            raise ValueError('DATABASE_URL must be a PostgreSQL connection string')
        return v

settings = Settings()
