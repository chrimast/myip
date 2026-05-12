from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    ipapi_is_key: str = ""
    ipapi_org_key: str = ""
    ipinfo_token: str = ""
    ipdata_key: str = ""
    myip_debug: bool = False
    myip_cache_ttl_seconds: int = 120
    myip_rate_limit_per_minute: int = 60

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    def key_status(self) -> dict[str, dict[str, bool | str]]:
        return {
            "ipapi_is_key": self._key_info(self.ipapi_is_key),
            "ipapi_org_key": self._key_info(self.ipapi_org_key),
            "ipinfo_token": self._key_info(self.ipinfo_token),
            "ipdata_key": self._key_info(self.ipdata_key),
        }

    def public_config(self) -> dict[str, int | bool]:
        return {
            "debug": self.myip_debug,
            "cache_ttl_seconds": self.myip_cache_ttl_seconds,
            "rate_limit_per_minute": self.myip_rate_limit_per_minute,
        }

    @staticmethod
    def _key_info(value: str) -> dict[str, bool | str]:
        return {"configured": bool(value), "source": "env" if value else "missing"}


def get_settings() -> Settings:
    return Settings()
