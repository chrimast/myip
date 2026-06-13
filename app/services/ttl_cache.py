from typing import Callable, Generic, TypeVar

T = TypeVar("T")


class TTLCache(Generic[T]):
    def __init__(self, ttl_seconds: int, now: Callable[[], float]) -> None:
        self.ttl_seconds = ttl_seconds
        self.now = now
        self.items: dict[str, tuple[float, T]] = {}

    def get(self, key: str) -> T | None:
        if cached := self.items.get(key):
            cached_at, value = cached
            if self.now() - cached_at < self.ttl_seconds:
                return value
        return None

    def set(self, key: str, value: T) -> None:
        self.items[key] = (self.now(), value)

    def clear(self) -> None:
        self.items.clear()
