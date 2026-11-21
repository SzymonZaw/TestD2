import unittest
from unittest.mock import patch
from browser_adapter import PlaywrightBrowserAdapter
from policy import ActionRequest, TaskContract, authorize_request, url_is_within_prefix


class URLPathScopeTests(unittest.TestCase):
    def setUp(self):
        self.contract = TaskContract(
            task_id="scope-test",
            allowed_actions=frozenset({"navigate", "read_page"}),
            allowed_origins=frozenset({"https://example.com"}),
            allowed_url_prefixes=frozenset({"https://example.com/public"}),
        )

    def test_allows_exact_prefix_and_descendants(self):
        for url in (
            "https://example.com/public",
            "https://example.com/public/",
            "https://example.com/public/articles/1",
        ):
            with self.subTest(url=url):
                self.assertTrue(url_is_within_prefix(url, self.contract.allowed_url_prefixes))

    def test_rejects_sibling_path_and_other_origin(self):
        self.assertFalse(url_is_within_prefix(
            "https://example.com/publicity", self.contract.allowed_url_prefixes
        ))
        self.assertFalse(url_is_within_prefix(
            "https://evil.example/public", self.contract.allowed_url_prefixes
        ))

    def test_rejects_traversal_encoded_separators_and_query_strings(self):
        for url in (
            "https://example.com/public/../admin",
            "https://example.com/public/%2e%2e/admin",
            "https://example.com/public%2f..%2fadmin",
            "https://example.com/public/%252fadmin",
            "https://example.com/public?action=logout",
        ):
            with self.subTest(url=url):
                self.assertFalse(url_is_within_prefix(url, self.contract.allowed_url_prefixes))

    def test_policy_denies_target_without_explicit_path_scope(self):
        no_scope = TaskContract(
            task_id="scope-test",
            allowed_actions=frozenset({"navigate"}),
            allowed_origins=frozenset({"https://example.com"}),
        )
        request = ActionRequest("scope-test", "navigate", "https://example.com/public", {})
        decision = authorize_request(request, no_scope)
        self.assertFalse(decision.allowed)
        self.assertIn("path", decision.reason.lower())

    def test_policy_denies_path_outside_scope(self):
        request = ActionRequest("scope-test", "navigate", "https://example.com/logout", {})
        decision = authorize_request(request, self.contract)
        self.assertFalse(decision.allowed)

    def test_policy_allows_scoped_path(self):
        request = ActionRequest("scope-test", "navigate", "https://example.com/public/page", {})
        decision = authorize_request(request, self.contract)
        self.assertTrue(decision.allowed)

class RequestInterceptionTests(unittest.TestCase):
    class Page:
        def route(self, pattern, handler):
            self.handler = handler

    class Request:
        def __init__(self, url, method="GET"):
            self.url = url
            self.method = method

    class Route:
        def __init__(self, url, method="GET"):
            self.request = RequestInterceptionTests.Request(url, method)
            self.continued = False
            self.aborted = False

        def continue_(self):
            self.continued = True

        def abort(self):
            self.aborted = True

    def setUp(self):
        self.page = self.Page()
        self.adapter = PlaywrightBrowserAdapter(
            self.page,
            {"https://example.com"},
            {"https://example.com/public"},
        )

    def test_allows_scoped_get_resource(self):
        route = self.Route("https://example.com/public/style.css")
        with patch("browser_adapter._has_public_destination", return_value=True):
            self.adapter._guard_request(route)
        self.assertTrue(route.continued)
        self.assertFalse(route.aborted)

    def test_blocks_post_even_inside_approved_path(self):
        route = self.Route("https://example.com/public/action", "POST")
        with patch("browser_adapter._has_public_destination", return_value=True):
            self.adapter._guard_request(route)
        self.assertFalse(route.continued)
        self.assertTrue(route.aborted)

    def test_blocks_get_outside_approved_path(self):
        route = self.Route("https://example.com/logout")
        with patch("browser_adapter._has_public_destination", return_value=True):
            self.adapter._guard_request(route)
        self.assertFalse(route.continued)
        self.assertTrue(route.aborted)

    def test_blocks_query_string_requests(self):
        route = self.Route("https://example.com/public?do=logout")
        with patch("browser_adapter._has_public_destination", return_value=True):
            self.adapter._guard_request(route)
        self.assertFalse(route.continued)
        self.assertTrue(route.aborted)


if __name__ == "__main__":
    unittest.main()
