"""Parent-side agent orchestration with an isolated browser worker process.

The OpenAI planner and policy gateway stay in the Streamlit process. Chromium,
Playwright and the page adapter run in a separate Python process that receives
only narrow read-only browser commands over a JSON-lines pipe.
"""
from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from pathlib import Path
from typing import Any, Iterable

from agent_runtime import AgentRunResult, Planner, BrowserAgentRuntime
from execution_gateway import ExecutionGateway
from policy import TaskContract
from provenance import TrackedText


class BrowserWorkerError(RuntimeError):
    """The isolated browser worker failed or violated its IPC contract."""


def _worker_environment() -> dict[str, str]:
    """Copy only non-secret environment values needed to launch Python/Chromium."""
    secret_markers = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")
    return {
        key: value
        for key, value in os.environ.items()
        if not any(marker in key.upper() for marker in secret_markers)
    }


class _BrowserWorkerClient:
    """Synchronous, bounded JSON-lines client; never exposes browser objects."""

    def __init__(
        self,
        allowed_origins: frozenset[str],
        allowed_url_prefixes: frozenset[str],
        *,
        headless: bool,
        startup_timeout: float = 45.0,
        request_timeout: float = 30.0,
    ) -> None:
        self._request_timeout = request_timeout
        self._next_id = 0
        self._responses: queue.Queue[str | None] = queue.Queue()
        worker_path = Path(__file__).with_name("browser_worker.py")
        self._process = subprocess.Popen(
            [sys.executable, "-I", str(worker_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            bufsize=1,
            env=_worker_environment(),
            cwd=str(worker_path.parent),
        )
        self._reader = threading.Thread(
            target=self._read_stdout, name="sentinel-browser-worker-reader", daemon=True
        )
        self._reader.start()
        try:
            ready = self._read_message(startup_timeout)
            if ready.get("type") != "ready":
                raise BrowserWorkerError("Browser worker did not complete startup")
            if ready.get("ok") is not True:
                raise BrowserWorkerError("Browser worker initialization failed")
            self._send({
                "id": 0,
                "command": "configure",
                "allowed_origins": sorted(allowed_origins),
                "allowed_url_prefixes": sorted(allowed_url_prefixes),
                "headless": bool(headless),
            })
            configured = self._read_message(startup_timeout)
            if configured.get("id") != 0 or configured.get("ok") is not True:
                raise BrowserWorkerError("Browser worker rejected its configuration")
        except Exception:
            self.close()
            raise

    def _read_stdout(self) -> None:
        stream = self._process.stdout
        if stream is None:
            self._responses.put(None)
            return
        try:
            for line in stream:
                self._responses.put(line)
        finally:
            self._responses.put(None)

    def _send(self, message: dict[str, Any]) -> None:
        if self._process.poll() is not None or self._process.stdin is None:
            raise BrowserWorkerError("Browser worker is not running")
        encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
        if len(encoded) > 8192:
            raise BrowserWorkerError("Browser worker command exceeds the IPC size limit")
        try:
            self._process.stdin.write(encoded + "\n")
            self._process.stdin.flush()
        except (BrokenPipeError, OSError) as exc:
            raise BrowserWorkerError("Could not send a command to the browser worker") from exc

    def _read_message(self, timeout: float) -> dict[str, Any]:
        try:
            line = self._responses.get(timeout=timeout)
        except queue.Empty as exc:
            raise BrowserWorkerError("Browser worker response timed out") from exc
        if line is None:
            raise BrowserWorkerError("Browser worker exited unexpectedly")
        if len(line) > 1_000_000:
            raise BrowserWorkerError("Browser worker response exceeded the size limit")
        try:
            message = json.loads(line)
        except (TypeError, ValueError) as exc:
            raise BrowserWorkerError("Browser worker returned invalid IPC data") from exc
        if not isinstance(message, dict):
            raise BrowserWorkerError("Browser worker returned an invalid message")
        return message

    def _request(self, action: str, target_url: str, arguments: dict[str, Any]) -> str:
        if action not in {"navigate", "read_page"}:
            raise BrowserWorkerError("Browser worker action is not permitted")
        if not isinstance(target_url, str) or len(target_url) > 2048:
            raise BrowserWorkerError("Browser worker URL is invalid")
        if arguments:
            raise BrowserWorkerError("Browser worker accepts no action arguments")
        self._next_id += 1
        request_id = self._next_id
        self._send({
            "id": request_id,
            "command": action,
            "target_url": target_url,
            "arguments": {},
        })
        response = self._read_message(self._request_timeout)
        if response.get("id") != request_id:
            raise BrowserWorkerError("Browser worker response ID mismatch")
        if response.get("ok") is not True:
            raise BrowserWorkerError("Browser worker denied or failed the browser operation")
        value = response.get("value", "")
        if not isinstance(value, str) or len(value) > 900_000:
            raise BrowserWorkerError("Browser worker returned an invalid or oversized result")
        return value

    def navigate(self, target_url: str, arguments: dict[str, Any]) -> str:
        return self._request("navigate", target_url, arguments)

    def read_page(self, target_url: str, arguments: dict[str, Any]) -> TrackedText:
        value = self._request("read_page", target_url, arguments)
        return TrackedText.from_web(value, target_url)

    @property
    def handlers(self) -> dict[str, Any]:
        return {"navigate": self.navigate, "read_page": self.read_page}

    def close(self) -> None:
        process = getattr(self, "_process", None)
        if process is None:
            return
        if process.poll() is None:
            try:
                if process.stdin is not None:
                    process.stdin.write(json.dumps({
                        "id": -1, "command": "close"
                    }) + "\n")
                    process.stdin.flush()
                process.wait(timeout=5)
            except (OSError, subprocess.TimeoutExpired):
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
        for stream_name in ("stdin", "stdout"):
            stream = getattr(process, stream_name, None)
            if stream is not None:
                try:
                    stream.close()
                except OSError:
                    pass


def run_browser_agent(
    task_id: str,
    planner: Planner,
    allowed_origins: Iterable[str],
    allowed_url_prefixes: Iterable[str],
    *,
    headless: bool = True,
    max_steps: int = 8,
) -> AgentRunResult:
    """Run the planner in the parent and browser actions in a separate process.

    The worker receives no planner, API client, API key, task text, or gateway.
    Its only input is a configured URL scope and narrow navigate/read_page RPCs.
    This is process separation, not an OS/container security sandbox.
    """
    origins = frozenset(allowed_origins)
    prefixes = frozenset(allowed_url_prefixes)
    contract = TaskContract(
        task_id=task_id,
        allowed_actions=frozenset({"navigate", "read_page"}),
        allowed_origins=origins,
        allowed_url_prefixes=prefixes,
    )
    worker = _BrowserWorkerClient(
        contract.allowed_origins,
        contract.allowed_url_prefixes,
        headless=headless,
    )
    try:
        gateway = ExecutionGateway(contract, worker.handlers)
        runtime = BrowserAgentRuntime(
            task_id=task_id,
            gateway=gateway,
            planner=planner,
            max_steps=max_steps,
        )
        return runtime.run()
    finally:
        worker.close()
