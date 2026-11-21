"""Isolated read-only browser worker.

This process owns Playwright and the browser page. It accepts only a fixed
JSON-lines protocol; it never receives the task prompt, planner, API client,
or API credentials from the parent process.
"""
from __future__ import annotations

import json
import sys
from typing import Any

from browser_adapter import PlaywrightBrowserAdapter


MAX_COMMAND_CHARS = 8192
MAX_PAGE_TEXT_CHARS = 400_000


def _write_message(message: dict[str, Any]) -> None:
    encoded = json.dumps(message, ensure_ascii=False, separators=(",", ":"))
    sys.stdout.write(encoded + "\n")
    sys.stdout.flush()


def _validate_command(message: Any, configured: bool) -> str:
    if not isinstance(message, dict):
        raise ValueError("IPC message must be an object")
    command = message.get("command")
    if not isinstance(command, str):
        raise ValueError("IPC command is missing")
    if not configured:
        if command != "configure" or set(message) != {
            "id", "command", "allowed_origins", "allowed_url_prefixes", "headless"
        }:
            raise ValueError("worker must receive exactly one valid configuration first")
        if message.get("id") != 0:
            raise ValueError("invalid configuration message ID")
        if not isinstance(message.get("allowed_origins"), list) or not message["allowed_origins"]:
            raise ValueError("worker requires a non-empty origin list")
        if not isinstance(message.get("allowed_url_prefixes"), list) or not message["allowed_url_prefixes"]:
            raise ValueError("worker requires a non-empty URL-prefix list")
        if not all(isinstance(item, str) and len(item) <= 2048 for item in (
            message["allowed_origins"] + message["allowed_url_prefixes"]
        )):
            raise ValueError("invalid URL scope configuration")
        if not isinstance(message.get("headless"), bool):
            raise ValueError("headless must be a boolean")
        return command
    if command == "close":
        if set(message) != {"id", "command"} or message.get("id") != -1:
            raise ValueError("invalid close message")
        return command
    if command not in {"navigate", "read_page"}:
        raise ValueError("browser action is not permitted")
    if set(message) != {"id", "command", "target_url", "arguments"}:
        raise ValueError("unexpected fields in browser command")
    if isinstance(message.get("id"), bool) or not isinstance(message.get("id"), int) or message["id"] < 1:
        raise ValueError("invalid browser command ID")
    if not isinstance(message.get("target_url"), str) or not message["target_url"] or len(message["target_url"]) > 2048:
        raise ValueError("invalid target URL")
    if message.get("arguments") != {}:
        raise ValueError("browser worker does not accept action arguments")
    return command


def main() -> int:
    # Parent and worker use an explicit UTF-8 JSON-lines protocol on Windows too.
    if hasattr(sys.stdin, "reconfigure"):
        sys.stdin.reconfigure(encoding="utf-8")
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    _write_message({"type": "ready", "ok": True})
    configured = False
    playwright_manager = None
    browser = None
    context = None
    adapter = None
    try:
        for raw_line in sys.stdin:
            if len(raw_line) > MAX_COMMAND_CHARS:
                _write_message({"ok": False, "error": "command_too_large"})
                return 2
            try:
                message = json.loads(raw_line)
                command = _validate_command(message, configured)
                if command == "configure":
                    from playwright.sync_api import sync_playwright

                    playwright_manager = sync_playwright()
                    playwright = playwright_manager.__enter__()
                    browser = playwright.chromium.launch(headless=message["headless"])
                    context = browser.new_context(
                        service_workers="block",
                        java_script_enabled=False,
                        accept_downloads=False,
                    )
                    context.set_default_timeout(10_000)
                    page = context.new_page()
                    adapter = PlaywrightBrowserAdapter(
                        page,
                        message["allowed_origins"],
                        message["allowed_url_prefixes"],
                    )
                    configured = True
                    _write_message({"id": 0, "ok": True})
                    continue
                if command == "close":
                    _write_message({"id": -1, "ok": True})
                    return 0
                if not configured or adapter is None:
                    raise ValueError("worker is not configured")
                if command == "navigate":
                    value = adapter.navigate(message["target_url"], {})
                else:
                    tracked = adapter.read_page(message["target_url"], {})
                    value = tracked.value
                if not isinstance(value, str):
                    raise ValueError("browser adapter returned a non-text result")
                _write_message({
                    "id": message["id"],
                    "ok": True,
                    "value": value[:MAX_PAGE_TEXT_CHARS],
                })
            except Exception:
                request_id = message.get("id") if isinstance(message, dict) else None
                _write_message({
                    "id": request_id,
                    "ok": False,
                    "error": "invalid_or_failed_browser_operation",
                })
                if not configured:
                    return 2
        return 0
    finally:
        if context is not None:
            try:
                context.close()
            except Exception:
                pass
        if browser is not None:
            try:
                browser.close()
            except Exception:
                pass
        if playwright_manager is not None:
            try:
                playwright_manager.__exit__(None, None, None)
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
