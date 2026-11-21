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
import tempfile
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
    """Pass only OS/runtime paths needed by Chromium, never application secrets."""
    allowed_names = {
        "PATH", "SYSTEMROOT", "WINDIR", "TEMP", "TMP",
        "LOCALAPPDATA", "APPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH",
        "PROGRAMFILES", "PROGRAMFILES(X86)", "PROGRAMW6432",
        "HOME", "TMPDIR", "DISPLAY", "XDG_RUNTIME_DIR",
        "PLAYWRIGHT_BROWSERS_PATH", "PLAYWRIGHT_NODEJS_PATH",
    }
    return {
        key: value
        for key, value in os.environ.items()
        if key.upper() in allowed_names
    }
