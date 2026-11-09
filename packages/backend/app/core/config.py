from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import model_validator
from typing import Optional, List
import os

class Settings(BaseSettings):
    # App Environment
    ENVIRONMENT: str = "development"  # "development", "test", "production"
    PORT: int = 8000
    
    # Core Databases
    DATABASE_URL: str = "postgresql://localhost:5432/aegivion_db"
    REDIS_URL: Optional[str] = "redis://localhost:6379/0"
    
    # Security Configuration
    SECRET_KEY: str = "development-secret-key"
    ENCRYPTION_KEY: Optional[str] = None
    JWT_ALGORITHM: str = "RS256"
    JWT_PRIVATE_KEY: Optional[str] = None
    JWT_PUBLIC_KEY: Optional[str] = None
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # AI & Integrations
    LLM_PROVIDER: str = "openai"
    OPENAI_API_KEY: Optional[str] = None
    GEMINI_API_KEY: Optional[str] = None
    AWS_ACCESS_KEY_ID: Optional[str] = None
    AWS_SECRET_ACCESS_KEY: Optional[str] = None
    AWS_REGION: str = "ap-south-1"

    # CORS settings
    CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://localhost:8000"
    ]

    model_config = SettingsConfigDict(
        env_file=(".env", ".env.test"),
        env_file_encoding="utf-8",
        extra="ignore"
    )

    @model_validator(mode="after")
    def validate_production_secrets(self) -> "Settings":
        if self.ENVIRONMENT.lower() == "production":
            critical_missing = []
            
            # Check DATABASE_URL
            if not self.DATABASE_URL or "localhost" in self.DATABASE_URL or "mongodb" in self.DATABASE_URL:
                critical_missing.append("Valid non-localhost DATABASE_URL")
                
            # Check SECRET_KEY
            if self.SECRET_KEY in ("development-secret-key", "", None) or len(self.SECRET_KEY) < 32:
                critical_missing.append("Production SECRET_KEY (min 32 characters)")
                
            # Check JWT RSA Private Key
            if not self.JWT_PRIVATE_KEY and not os.getenv("JWT_PRIVATE_KEY"):
                critical_missing.append("JWT_PRIVATE_KEY environment variable")

            # Check ENCRYPTION_KEY
            if not self.ENCRYPTION_KEY and not os.getenv("ENCRYPTION_KEY"):
                critical_missing.append("ENCRYPTION_KEY environment variable")
                
            if critical_missing:
                raise ValueError(
                    f"PRODUCTION CONFIGURATION FATAL ERROR: Missing critical secrets: {', '.join(critical_missing)}"
                )
        return self

settings = Settings()
