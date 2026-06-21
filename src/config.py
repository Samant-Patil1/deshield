from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="DEPSHIELD_")

    google_api_key: str = Field(alias="GOOGLE_API_KEY")
    github_token: str | None = Field(default=None, alias="GITHUB_TOKEN")
    env: str = "development"
    max_repo_size_mb: int = 50
    clone_timeout_seconds: int = 60
    osv_api_url: str = "https://api.osv.dev/v1"
    pypi_api_url: str = "https://pypi.org/pypi"
    npm_registry_url: str = "https://registry.npmjs.org"

settings = Settings()
