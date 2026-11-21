import unittest
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


if __name__ == "__main__":
    unittest.main()
