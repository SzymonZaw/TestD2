"""One-call launcher for the read-only Playwright agent runtime.

Playwright is imported lazily so the core Sentinel package and unit tests do
not require the optional browser dependency.
"""
from __future__ import annotations

from typing import Iterable

from agent_runtime import AgentRunResult, Planner, BrowserAgentRuntime
from browser_adapter import PlaywrightBrowserAdapter
from execution_gateway import ExecutionGateway
from policy import TaskContract


def run_browser_agent(
    task_id: str,
    planner: Planner,
    allowed_origins: Iterable[str],
    allowed_url_prefixes: Iterable[str],
    *,
    headless: bool = True,
    max_steps: int = 8,
) -> AgentRunResult:
    """Launch Chromium and run a planner with navigate/read_page only.

    Browser, context and page handles remain inside this function. Service
    workers are disabled so page-level request interception cannot be bypassed
    by a registered service worker. The caller receives observations only.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Playwright is optional; install it with "
            "'python -m pip install playwright' and "
            "'python -m playwright install chromium'"
        ) from exc

    origins = frozenset(allowed_origins)
    contract = TaskContract(
        task_id=task_id,
        allowed_actions=frozenset({"navigate", "read_page"}),
        allowed_origins=origins,
        allowed_url_prefixes=frozenset(allowed_url_prefixes),
    )

    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=headless)
        try:
            context = browser.new_context(service_workers="block", java_script_enabled=False)
            try:
                page = context.new_page()
                adapter = PlaywrightBrowserAdapter(page, origins, contract.allowed_url_prefixes)
                gateway = ExecutionGateway(contract, adapter.handlers)
                runtime = BrowserAgentRuntime(
                    task_id=task_id,
                    gateway=gateway,
                    planner=planner,
                    max_steps=max_steps,
                )
                return runtime.run()
            finally:
                context.close()
        finally:
            browser.close()
