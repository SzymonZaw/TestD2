import tempfile
import unittest
from pathlib import Path

from api_usage import ApiUsageLedger, DailyApiLimitExceeded


class ApiUsageLedgerTests(unittest.TestCase):
    def test_reserves_requests_until_daily_limit(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = ApiUsageLedger(Path(directory) / "usage.sqlite3")
            self.assertEqual(ledger.reserve_request(2), 1)
            self.assertEqual(ledger.reserve_request(2), 2)
            with self.assertRaises(DailyApiLimitExceeded):
                ledger.reserve_request(2)
            self.assertEqual(ledger.snapshot()["request_count"], 2)

    def test_records_token_usage(self):
        with tempfile.TemporaryDirectory() as directory:
            ledger = ApiUsageLedger(Path(directory) / "usage.sqlite3")
            ledger.reserve_request(3)
            ledger.record_tokens(17, 9)
            usage = ledger.snapshot()
            self.assertEqual(usage["prompt_tokens"], 17)
            self.assertEqual(usage["completion_tokens"], 9)
            self.assertEqual(usage["total_tokens"], 26)


if __name__ == "__main__":
    unittest.main()
