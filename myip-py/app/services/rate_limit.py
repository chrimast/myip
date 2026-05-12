from typing import Callable


class RateLimiter:
    def __init__(self, limit: int, now: Callable[[], float], window_seconds: int = 60) -> None:
        self.limit = limit
        self.now = now
        self.window_seconds = window_seconds
        self.windows: dict[str, tuple[float, int]] = {}

    def allow(self, key: str) -> bool:
        now = self.now()
        start, count = self.windows.get(key, (now, 0))
        if now - start >= self.window_seconds:
            start, count = now, 0
        if count >= self.limit:
            return False
        self.windows[key] = (start, count + 1)
        return True

    def clear(self) -> None:
        self.windows.clear()
