from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    # API keys
    shodan_api_key: str = ""
    securitytrails_api_key: str = ""
    virustotal_api_key: str = ""
    censys_api_id: str = ""
    censys_api_secret: str = ""
    github_token: str = ""
    urlscan_api_key: str = ""

    # Concurrency
    dns_concurrency: int = Field(default=500)
    http_concurrency: int = Field(default=50)
    crawl_concurrency: int = Field(default=10)
    fuzz_concurrency: int = Field(default=5)

    # Timeouts
    http_timeout: int = Field(default=10)
    dns_timeout: int = Field(default=5)

    # Crawl
    max_crawl_depth: int = Field(default=5)

    # Output
    db_path: str = "dreakon.db"


settings = Settings()
