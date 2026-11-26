"""Async SQLite (WAL mode) Threat Intelligence cache with per-provider and negative TTL."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from pathlib import Path

import aiosqlite
from pydantic import ValidationError

from vtx_ti_enricher.models import CacheStats, IOCType, ProviderResult, ProviderStatus

DEFAULT_PROVIDER_TTLS: dict[str, int] = {
    "urlhaus": 3600,        # 1h — active malware URLs rotate quickly
    "abuseipdb": 21600,     # 6h — dynamic IP reputation
    "virustotal": 21600,    # 6h — multi-AV detections evolve
    "otx": 43200,           # 12h — threat pulses
}

_CACHEABLE_STATUSES = {ProviderStatus.OK, ProviderStatus.NOT_FOUND}

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS ti_cache (
    provider TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    status TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    stored_at REAL NOT NULL,
    expires_at REAL NOT NULL,
    PRIMARY KEY (provider, ioc_type, ioc_value)
);
CREATE INDEX IF NOT EXISTS idx_ti_cache_expires_at ON ti_cache (expires_at);
"""


class AsyncSQLiteCache:
    """Persistent async SQLite cache (WAL) with per-provider TTL and negative-cache control."""

    def __init__(
        self,
        db_path: Path | str = Path(".vtx_ti_cache.sqlite3"),
        default_ttl_seconds: int = 21600,
        provider_ttls: dict[str, int] | None = None,
        not_found_ttl_seconds: int = 900,
        busy_timeout_ms: int = 5000,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.db_path = Path(db_path)
        self.default_ttl_seconds = max(1, int(default_ttl_seconds))
        merged_ttls = dict(DEFAULT_PROVIDER_TTLS)
        if provider_ttls:
            for k, v in provider_ttls.items():
                merged_ttls[k.strip().lower()] = max(1, int(v))
        self.provider_ttls = merged_ttls
        self.not_found_ttl_seconds = max(1, int(not_found_ttl_seconds))
        self.busy_timeout_ms = max(100, int(busy_timeout_ms))
        self._clock = clock

        self._conn: aiosqlite.Connection | None = None
        self._journal_mode: str = "unknown"
        self._lock = asyncio.Lock()

    async def __aenter__(self) -> AsyncSQLiteCache:
        await self.initialize()
        return self

    async def __aexit__(self, exc_type: object, exc: object, tb: object) -> None:
        await self.close()

    def _require_conn(self) -> aiosqlite.Connection:
        if self._conn is None:
            raise RuntimeError("AsyncSQLiteCache connection is not initialized")
        return self._conn

    def resolve_ttl(self, provider: str, status: ProviderStatus) -> int:
        """Compute effective TTL in seconds for a provider and outcome status."""
        base = self.provider_ttls.get(provider.lower(), self.default_ttl_seconds)
        if status == ProviderStatus.NOT_FOUND:
            return min(base, self.not_found_ttl_seconds)
        return base

    async def initialize(self) -> None:
        """Open connection, enable WAL mode, and ensure cache schema exists."""
        async with self._lock:
            if self._conn is not None:
                return
            if str(self.db_path) != ":memory:":
                self.db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = await aiosqlite.connect(str(self.db_path))
            await conn.execute(f"PRAGMA busy_timeout = {self.busy_timeout_ms}")
            cursor = await conn.execute("PRAGMA journal_mode = WAL")
            row = await cursor.fetchone()
            await cursor.close()
            self._journal_mode = str(row[0]).lower() if row and row[0] else "unknown"
            await conn.execute("PRAGMA synchronous = NORMAL")
            await conn.execute("PRAGMA temp_store = MEMORY")
            await conn.executescript(_SCHEMA_SQL)
            await conn.commit()
            self._conn = conn

    async def close(self) -> None:
        """Close the underlying SQLite connection cleanly."""
        async with self._lock:
            if self._conn is not None:
                await self._conn.close()
                self._conn = None

    async def get(
        self,
        provider: str,
        ioc_type: IOCType,
        ioc_value: str,
    ) -> ProviderResult | None:
        """Return a non-expired cached ProviderResult or None on miss/expiration."""
        if self._conn is None:
            await self.initialize()
        now = self._clock()
        prov_key = provider.strip().lower()

        async with self._lock:
            conn = self._require_conn()
            cursor = await conn.execute(
                """
                SELECT payload_json, expires_at
                FROM ti_cache
                WHERE provider = ? AND ioc_type = ? AND ioc_value = ?
                """,
                (prov_key, ioc_type.value, ioc_value),
            )
            row = await cursor.fetchone()
            await cursor.close()

            if row is None:
                return None

            payload_json, expires_at = str(row[0]), float(row[1])
            if expires_at <= now:
                await conn.execute(
                    """
                    DELETE FROM ti_cache
                    WHERE provider = ? AND ioc_type = ? AND ioc_value = ?
                    """,
                    (prov_key, ioc_type.value, ioc_value),
                )
                await conn.commit()
                return None

            try:
                cached = ProviderResult.model_validate_json(payload_json)
            except ValidationError:
                await conn.execute(
                    """
                    DELETE FROM ti_cache
                    WHERE provider = ? AND ioc_type = ? AND ioc_value = ?
                    """,
                    (prov_key, ioc_type.value, ioc_value),
                )
                await conn.commit()
                return None

            return cached.model_copy(
                update={"from_cache": True, "attempts": 0, "latency_ms": 0.0}
            )

    async def set(
        self,
        ioc_type: IOCType,
        ioc_value: str,
        result: ProviderResult,
        ttl_seconds: int | None = None,
    ) -> bool:
        """Persist OK or NOT_FOUND provider outcomes; skip transient failures and skips."""
        if result.status not in _CACHEABLE_STATUSES:
            return False
        if self._conn is None:
            await self.initialize()

        now = self._clock()
        ttl = (
            max(1, int(ttl_seconds))
            if ttl_seconds is not None
            else self.resolve_ttl(result.provider, result.status)
        )
        expires_at = now + ttl
        clean_result = result.model_copy(update={"from_cache": False})
        payload_json = clean_result.model_dump_json()

        async with self._lock:
            conn = self._require_conn()
            await conn.execute(
                """
                INSERT INTO ti_cache (
                    provider, ioc_type, ioc_value, status, payload_json, stored_at, expires_at
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(provider, ioc_type, ioc_value) DO UPDATE SET
                    status = excluded.status,
                    payload_json = excluded.payload_json,
                    stored_at = excluded.stored_at,
                    expires_at = excluded.expires_at
                """,
                (
                    result.provider.strip().lower(),
                    ioc_type.value,
                    ioc_value,
                    result.status.value,
                    payload_json,
                    now,
                    expires_at,
                ),
            )
            await conn.commit()
            return True

    async def purge_expired(self) -> int:
        """Delete all expired rows and return the number of removed entries."""
        if self._conn is None:
            await self.initialize()
        now = self._clock()
        async with self._lock:
            conn = self._require_conn()
            cursor = await conn.execute(
                "DELETE FROM ti_cache WHERE expires_at <= ?",
                (now,),
            )
            deleted = cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
            await cursor.close()
            await conn.commit()
            return deleted

    async def clear(self) -> int:
        """Remove all rows from the cache table."""
        if self._conn is None:
            await self.initialize()
        async with self._lock:
            conn = self._require_conn()
            cursor = await conn.execute("DELETE FROM ti_cache")
            deleted = cursor.rowcount if cursor.rowcount and cursor.rowcount > 0 else 0
            await cursor.close()
            await conn.commit()
            return deleted

    async def stats(self) -> CacheStats:
        """Return active, expired, journal-mode, and per-provider cache statistics."""
        if self._conn is None:
            await self.initialize()
        now = self._clock()
        async with self._lock:
            conn = self._require_conn()
            cur_tot = await conn.execute(
                """
                SELECT
                    COUNT(*),
                    SUM(CASE WHEN expires_at > ? THEN 1 ELSE 0 END),
                    SUM(CASE WHEN expires_at <= ? THEN 1 ELSE 0 END)
                FROM ti_cache
                """,
                (now, now),
            )
            row = await cur_tot.fetchone()
            await cur_tot.close()

            total = int(row[0] or 0) if row else 0
            active = int(row[1] or 0) if row else 0
            expired = int(row[2] or 0) if row else 0

            cur_prov = await conn.execute(
                """
                SELECT provider, COUNT(*)
                FROM ti_cache
                WHERE expires_at > ?
                GROUP BY provider
                ORDER BY provider
                """,
                (now,),
            )
            prov_rows = await cur_prov.fetchall()
            await cur_prov.close()

            return CacheStats(
                db_path=str(self.db_path),
                journal_mode=self._journal_mode,
                total_entries=total,
                active_entries=active,
                expired_entries=expired,
                by_provider={str(r[0]): int(r[1]) for r in prov_rows},
            )
