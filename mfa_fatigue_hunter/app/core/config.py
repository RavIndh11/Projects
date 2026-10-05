from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    API_KEY: str = "default-dev-key"
    LOG_LEVEL: str = "INFO"
    FATIGUE_THRESHOLD_SECONDS: int = 300
    FATIGUE_COUNT_THRESHOLD: int = 3

    class Config:
        env_file = ".env"

settings = Settings()
