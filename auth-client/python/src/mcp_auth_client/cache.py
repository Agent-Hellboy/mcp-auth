import time
from collections import OrderedDict
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class CachedValue:
    value: object
    expires_at: float


class BoundedTokenCache:
    """A bounded LRU cache that never returns values inside the expiry margin."""

    def __init__(self, max_entries: int = 128, expiry_margin: float = 30.0) -> None:
        if max_entries < 1:
            raise ValueError("max_entries must be positive")
        if expiry_margin < 0:
            raise ValueError("expiry_margin must be non-negative")
        self.max_entries = max_entries
        self.expiry_margin = expiry_margin
        self._values: OrderedDict[str, CachedValue] = OrderedDict()

    def get(self, key: str, now: float | None = None) -> object | None:
        value = self._values.get(key)
        current = time.time() if now is None else now
        if value is None:
            return None
        if value.expires_at <= current + self.expiry_margin:
            self._values.pop(key, None)
            return None
        self._values.move_to_end(key)
        return value.value

    def put(self, key: str, value: object, expires_at: float) -> None:
        self._values[key] = CachedValue(value, expires_at)
        self._values.move_to_end(key)
        while len(self._values) > self.max_entries:
            self._values.popitem(last=False)

    def __len__(self) -> int:
        return len(self._values)
