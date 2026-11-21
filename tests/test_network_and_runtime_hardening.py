import socket
import unittest
from unittest.mock import patch

from agent_runtime import AgentProposal, BrowserAgentRuntime
from browser_adapter import _has_public_destination
from execution_gateway import ExecutionGateway
from policy import TaskContract


class DestinationGuardTests(unittest.TestCase):
    def test_rejects_loopback_private_and_localhost(self):
        self.assertFalse(_has_public_destination("http://127.0.0.1/"))
        self.assertFalse(_has_public_destination("http://10.0.0.8/"))
        self.assertFalse(_has_public_destination("http://localhost/"))
        self.assertFalse(_has_public_destination("http://service.localhost/"))

    def test_accepts_public_ip_literal(self):
        self.assertTrue(_has_public_destination("https://8.8.8.8/"))

    def test_rejects_hostname_resolving_to_private_address(self):
        private_record = (
            socket.AF_INET, socket.SOCK_STREAM, 6, "",
            ("192.168.1.10", 443),
        )
        with patch("browser_adapter.socket.getaddrinfo", return_value=[private_record]):
            self.assertFalse(_has_public_destination("https://example.test/"))

    def test_rejects_dns_resolution_failure(self):
        with patch("browser_adapter.socket.getaddrinfo", side_effect=OSError("DNS unavailable")):
            self.assertFalse(_has_public_destination("https://example.test/"))


class RuntimeFailClosedTests(unittest.TestCase):
    def test_gateway_handler_exception_stops_run(self):
        contract = TaskContract(
            task_id="task-2",
            allowed_actions=frozenset({"navigate"}),
            allowed_origins=frozenset({"https://example.com"}),
            allowed_url_prefixes=frozenset({"https://example.com/"}),
        )

        def broken_handler(url, args):
            raise RuntimeError("browser navigation failed")

        gateway = ExecutionGateway(contract, {"navigate": broken_handler})
        runtime = BrowserAgentRuntime(
            task_id="task-2",
            gateway=gateway,
            planner=lambda history: AgentProposal(
                "navigate", "https://example.com/", {}
            ),
            max_steps=1,
        )

        result = runtime.run()

        self.assertFalse(result.completed)
        self.assertEqual(result.stopped_reason, "gateway_execution_error")

    def test_approval_provider_exception_stops_run_without_execution(self):
        executed = []
        contract = TaskContract(
            task_id="task-1",
            allowed_actions=frozenset({"navigate"}),
            allowed_origins=frozenset({"https://example.com"}),
        )
        gateway = ExecutionGateway(
            contract,
            {"navigate": lambda url, args: executed.append(url)},
        )

        def planner(history):
            return AgentProposal("navigate", "https://example.com/", {})

        def broken_approval_provider(request):
            raise RuntimeError("approval service unavailable")

        runtime = BrowserAgentRuntime(
            task_id="task-1",
            gateway=gateway,
            planner=planner,
            approval_provider=broken_approval_provider,
            max_steps=2,
        )
        result = runtime.run()

        self.assertFalse(result.completed)
        self.assertEqual(result.stopped_reason, "request_or_approval_error")
        self.assertEqual(executed, [])


if __name__ == "__main__":
    unittest.main()
