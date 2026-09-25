import json
import unittest
from unittest.mock import patch

from fastapi import Response

from routes import tacacs


class TacacsTimingTests(unittest.TestCase):
    def test_attach_timing_headers_sets_processing_and_total(self):
        response = Response(content="ok")
        with patch.object(tacacs.time, "perf_counter", side_effect=[100.0, 100.123]):
            updated = tacacs.attach_timing_headers(response, 100.0, total_count=7)
        self.assertIs(updated, response)
        self.assertEqual(response.headers.get("X-Processing-Ms"), "123")
        self.assertEqual(response.headers.get("X-Total-Count"), "7")

    def test_list_policy_versions_keeps_list_contract_and_headers(self):
        fake_rows = [{"id": "v1"}, {"id": "v2"}]
        with patch.object(tacacs, "_policy_versions", return_value=fake_rows):
            with patch.object(tacacs.time, "perf_counter", side_effect=[10.0, 10.050]):
                response = tacacs.list_tacacs_policy_versions(payload={"sub": "admin"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("X-Processing-Ms"), "50")
        self.assertEqual(response.headers.get("X-Total-Count"), "2")
        self.assertEqual(json.loads(response.body.decode("utf-8")), fake_rows)

    def test_get_redacted_file_sets_timing_header(self):
        with patch.object(tacacs, "_get_redacted_snapshot_file", return_value=None):
            with self.assertRaises(Exception):
                tacacs.get_tacacs_policy_version_redacted_file("v1", "x", payload={"sub": "admin"})

        with patch.object(tacacs, "_get_redacted_snapshot_file") as fake_get_path, patch.object(
            tacacs, "_read_text_limited", return_value=("abc", False, 3)
        ), patch.object(tacacs.time, "perf_counter", side_effect=[20.0, 20.009]):
            class _DummyPath:
                name = "demo.redacted"

            fake_get_path.return_value = _DummyPath()
            response = tacacs.get_tacacs_policy_version_redacted_file("v1", "demo.redacted", payload={"sub": "admin"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("X-Processing-Ms"), "9")


if __name__ == "__main__":
    unittest.main()
