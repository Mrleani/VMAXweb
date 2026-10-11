from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="VMAX_", extra="ignore")

    app_name: str = "VMAXweb Security Engine"
    environment: str = "development"

    # HTTP client behaviour
    request_timeout: float = 12.0
    max_concurrency: int = 20
    user_agent: str = "VMAXweb-Scanner/0.1 (+https://vmaxweb.io/bot)"

    # Port scanner
    port_timeout: float = 2.5
    port_scan_enabled: bool = True

    # Subdomain discovery
    subdomain_limit: int = 50

    # Safety: active checks (ports/subdomains) require a verified target
    require_verified_target: bool = True
    allowed_schemes: tuple[str, ...] = ("http", "https")

    # CORS origins allowed to call the API (the Next.js frontend)
    cors_origins: tuple[str, ...] = ("http://localhost:3000",)

    # Supabase persistence (PostgREST). Leave blank to use the in-memory store.
    supabase_url: str = ""
    supabase_service_key: str = ""
    supabase_jwt_secret: str = ""
    auth_required: bool = False

    # Free plan guardrail
    free_monthly_scan_limit: int = 5

    @property
    def is_production(self) -> bool:
        return self.environment.lower() in {"production", "prod"}


@lru_cache
def get_settings() -> Settings:
    return Settings()
