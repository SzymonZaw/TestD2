"""Local, process-safe daily limits and usage accounting for OpenAI requests."""
from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from typing import Iterator
from datetime import datetime, timezone
from pathlib import Path


class DailyApiLimitExceeded(RuntimeError):
    """Raised before an OpenAI request when the daily cap has been reached."""


class ApiUsageLedger:
    """SQLite-backed daily request/token ledger shared by app sessions."""

    def __init__(self, path: str | Path) -> None:
        self.path = str(path)
        with self._connection() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS api_usage (
                    usage_date TEXT PRIMARY KEY,
                    request_count INTEGER NOT NULL DEFAULT 0,
                    prompt_tokens INTEGER NOT NULL DEFAULT 0,
                    completion_tokens INTEGER NOT NULL DEFAULT 0
                )
                """
            )

    @staticmethod
    def _today() -> str:
        return datetime.now(timezone.utc).date().isoformat()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=10)
        connection.row_factory = sqlite3.Row
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def reserve_request(self, daily_limit: int) -> int:
        if isinstance(daily_limit, bool) or not isinstance(daily_limit, int) or daily_limit < 1:
            raise ValueError("daily_limit must be a positive integer")
        today = self._today()
        with self._connection() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "INSERT OR IGNORE INTO api_usage(usage_date) VALUES(?)", (today,)
            )
            row = connection.execute(
                "SELECT request_count FROM api_usage WHERE usage_date=?", (today,)
            ).fetchone()
            if row["request_count"] >= daily_limit:
                connection.rollback()
                raise DailyApiLimitExceeded(
                    f"Dzienny limit OpenAI został osiągnięty ({daily_limit} zapytań)."
                )
            next_count = row["request_count"] + 1
            connection.execute(
                "UPDATE api_usage SET request_count=? WHERE usage_date=?",
                (next_count, today),
            )
            connection.commit()
            return next_count

    def record_tokens(self, prompt_tokens: int, completion_tokens: int) -> None:
        prompt = max(0, int(prompt_tokens))
        completion = max(0, int(completion_tokens))
        with self._connection() as connection:
            connection.execute(
                """
                UPDATE api_usage
                SET prompt_tokens=prompt_tokens+?,
                    completion_tokens=completion_tokens+?
                WHERE usage_date=?
                """,
                (prompt, completion, self._today()),
            )

    def snapshot(self) -> dict[str, int | str]:
        today = self._today()
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM api_usage WHERE usage_date=?", (today,)
            ).fetchone()
        if row is None:
            return {
                "date_utc": today, "request_count": 0,
                "prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0,
            }
        prompt = int(row["prompt_tokens"])
        completion = int(row["completion_tokens"])
        return {
            "date_utc": today,
            "request_count": int(row["request_count"]),
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
        }
