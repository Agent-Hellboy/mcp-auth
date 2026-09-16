from types import TracebackType
from typing import Self

import httpx


class AsyncHTTPClient:
    """Small lifecycle-managed HTTP client used by discovery and token helpers."""

    def __init__(self, client: httpx.AsyncClient | None = None) -> None:
        self._client = client
        self._owned = client is None

    async def __aenter__(self) -> Self:
        if self._client is None:
            self._client = httpx.AsyncClient(follow_redirects=False)
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._owned and self._client is not None:
            await self._client.aclose()

    @property
    def client(self) -> httpx.AsyncClient:
        if self._client is None:
            raise RuntimeError("AsyncHTTPClient must be used as an async context manager")
        return self._client


async def json_get(client: httpx.AsyncClient, url: str) -> dict[str, object]:
    response = await client.get(url, headers={"Accept": "application/json"})
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError(f"expected JSON object from {url}")
    return data
