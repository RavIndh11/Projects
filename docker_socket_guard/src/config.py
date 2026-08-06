from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    log_level: str = "INFO"
    allow_privileged_mode: bool = False
    read_only_mode: bool = False

    class Config:
        env_file = ".env"

settings = Settings()
