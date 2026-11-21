"""Narrow synchronous Playwright adapter for Sentinel's guarded browser actions.

Only navigation and page-text extraction are exposed. The adapter installs a
request interceptor that permits HTTP(S) requests only to task-approved origins.
It deliberately does not expose click, fill, submit, download, or arbitrary JS.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Any, Iterable
from urllib.parse import urlsplit

from provenance import TrackedText


def _has_public_destination(url: str) -> bool:
    """Reject loopback/private/link-local/reserved destinations.

    DNS is checked at interception time as defense in depth. This is not a
    substitute for network-level egress filtering: DNS can change between this
    check and Chromium's connection (DNS rebinding/TOCTOU).
    """
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        if not host:
            return False
        normalized = host.rstrip(".").lower()
        if normalized == "localhost" or normalized.endswith(".localhost"):
            return False
        try:
            addresses = {ipaddress.ip_address(normalized)}
        except ValueError:
            records = socket.getaddrinfo(
                normalized, parsed.port or (443 if parsed.scheme.lower() == "https" else 80),
                type=socket.SOCK_STREAM,
            )
            addresses = {ipaddress.ip_address(record[4][0]) for record in records}
        return bool(addresses) and all(address.is_global for address in addresses)
    except (OSError, ValueError, TypeError):
        return False


def _origin(url: str) -> str:
    try:
        parsed = urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError("only absolute HTTP(S) URLs are supported")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("URL credentials are not allowed")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        port = parsed.port
    except (AttributeError, UnicodeError, ValueError) as exc:
        raise ValueError("invalid HTTP(S) URL") from exc
    default_port = 80 if parsed.scheme.lower() == "http" else 443
    return f"{parsed.scheme.lower()}://{host}" + (
        f":{port}" if port is not None and port != default_port else ""
    )


class PlaywrightBrowserAdapter:
    """Expose safe, read-oriented handlers for an existing sync Playwright page.

    Pass the same allowed-origin set to TaskContract and this adapter. The
    gateway remains the only supported entry point for these handlers.
    """

    def __init__(self, page: Any, allowed_origins: Iterable[str]) -> None:
        if page is None or not callable(getattr(page, "route", None)):
            raise TypeError("page must be a synchronous Playwright Page-like object")
        if isinstance(allowed_origins, str):
            raise TypeError("allowed_origins must be a collection, not a string")
        self._page = page
        self._allowed_origins = frozenset(_origin(item) for item in allowed_origins)
        if not self._allowed_origins:
            raise ValueError("at least one allowed origin is required")
        # Intercept every document and subresource request, including redirects.
        self._page.route("**/*", self._guard_request)

    @property
    def handlers(self) -> dict[str, Any]:
        """Handlers to pass directly to ExecutionGateway."""
        return {
            "navigate": self.navigate,
            "read_page": self.read_page,
        }

    def _guard_request(self, route: Any) -> None:
        try:
            request_url = route.request.url
            allowed = (
                _origin(request_url) in self._allowed_origins
                and _has_public_destination(request_url)
            )
        except (AttributeError, TypeError, ValueError):
            allowed = False
        if allowed:
            route.continue_()
        else:
            route.abort()

    def navigate(self, target_url: str, arguments: dict[str, Any]) -> str:
        if arguments:
            raise ValueError("navigate does not accept additional arguments")
        if _origin(target_url) not in self._allowed_origins:
            raise PermissionError("navigation target is outside the adapter origin allowlist")
        if not _has_public_destination(target_url):
            raise PermissionError("navigation target resolves to a non-public or unverifiable address")
        self._page.goto(target_url, wait_until="domcontentloaded")
        final_url = self._page.url
        if _origin(final_url) not in self._allowed_origins:
            raise PermissionError("navigation ended outside the adapter origin allowlist")
        return final_url

    def read_page(self, target_url: str, arguments: dict[str, Any]) -> TrackedText:
        if arguments:
            raise ValueError("read_page does not accept additional arguments")
        current_url = self._page.url
        if _origin(target_url) not in self._allowed_origins:
            raise PermissionError("read target is outside the adapter origin allowlist")
        if _origin(current_url) not in self._allowed_origins:
            raise PermissionError("current page is outside the adapter origin allowlist")
        if _origin(current_url) != _origin(target_url):
            raise PermissionError("read target origin does not match the current page")
        text = self._page.locator("body").inner_text()
        return TrackedText.from_web(text, current_url)
