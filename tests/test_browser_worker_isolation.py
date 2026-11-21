import os
import unittest
from unittest.mock import patch

from browser_worker import _validate_command
from playwright_runner import _worker_environment


class BrowserWorkerProtocolTests(unittest.TestCase):
    def test_worker_requires_configuration_before_actions(self):
        command = {
            "id": 0,
            "command": "configure",
            "allowed_origins": ["https://example.com"],
            "allowed_url_prefixes": ["https://example.com/public"],
            "headless": True,
        }
        self.assertEqual(_validate_command(command, configured=False), "configure")

    def test_worker_rejects_action_before_configuration(self):
        with self.assertRaises(ValueError):
            _validate_command({
                "id": 1,
                "command": "navigate",
                "target_url": "https://example.com/public",
                "arguments": {},
            }, configured=False)

    def test_worker_accepts_only_fixed_read_only_actions(self):
        for action in ("navigate", "read_page"):
            with self.subTest(action=action):
                message = {
                    "id": 1,
                    "command": action,
                    "target_url": "https://example.com/public/page",
                    "arguments": {},
                }
                self.assertEqual(_validate_command(message, configured=True), action)

    def test_worker_rejects_unknown_action_and_extra_fields(self):
        with self.assertRaises(ValueError):
            _validate_command({
                "id": 1,
                "command": "execute_javascript",
                "target_url": "https://example.com/public",
                "arguments": {},
            }, configured=True)
        with self.assertRaises(ValueError):
            _validate_command({
                "id": 1,
                "command": "navigate",
                "target_url": "https://example.com/public",
                "arguments": {},
                "script": "alert(1)",
            }, configured=True)

    def test_worker_rejects_non_empty_arguments(self):
        with self.assertRaises(ValueError):
            _validate_command({
                "id": 1,
                "command": "navigate",
                "target_url": "https://example.com/public",
                "arguments": {"url": "https://evil.example"},
            }, configured=True)

    def test_worker_environment_does_not_inherit_api_or_other_secret_values(self):
        with patch.dict(os.environ, {
            "OPENAI_API_KEY": "must-not-be-copied",
            "SERVICE_TOKEN": "must-not-be-copied",
            "DATABASE_PASSWORD": "must-not-be-copied",
            "PATH": os.environ.get("PATH", ""),
        }, clear=False):
            environment = _worker_environment()
        self.assertNotIn("OPENAI_API_KEY", environment)
        self.assertNotIn("SERVICE_TOKEN", environment)
        self.assertNotIn("DATABASE_PASSWORD", environment)
        self.assertIn("PATH", environment)
        self.assertNotIn("SENTINEL_OPENAI_MODEL", environment)


if __name__ == "__main__":
    unittest.main()
