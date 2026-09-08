"""
Unit tests for server.py (local web server and upload API).
"""

import json
import threading
import time
import unittest
import urllib.request
import urllib.error
from http.server import HTTPServer
from pathlib import Path

import sys
BASE_DIR = Path(__file__).parent.parent.resolve()
sys.path.insert(0, str(BASE_DIR))
sys.path.insert(0, str(BASE_DIR / "src"))

from server import BOMServerHandler, process_bom_file


class TestBOMServer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start test HTTP server on an ephemeral port
        cls.httpd = HTTPServer(("127.0.0.1", 0), BOMServerHandler)
        cls.port = cls.httpd.server_port
        cls.base_url = f"http://127.0.0.1:{cls.port}"
        cls.server_thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.server_thread.start()
        time.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def test_get_index_html(self):
        req = urllib.request.Request(f"{self.base_url}/")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            self.assertIn("text/html", resp.headers.get("Content-Type"))
            html = resp.read().decode("utf-8")
            self.assertIn("Supply Chain Risk Scoring Tool", html)
            self.assertIn("Server BOM Ingestion Portal", html)
            self.assertIn("CycloneDX", html)

    def test_sample_cyclonedx(self):
        req = urllib.request.Request(f"{self.base_url}/api/samples/cyclonedx")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["format"], "CycloneDX JSON")
            self.assertEqual(data["aggregate_score"], 62.7)
            self.assertEqual(data["scored_count"], 3)
            self.assertEqual(data["unscored_count"], 2)
            self.assertEqual(data["ingestion_errors"], 1)

            # Test report link can be retrieved
            report_url = f"{self.base_url}{data['report_html_url']}"
            with urllib.request.urlopen(report_url) as r_resp:
                self.assertEqual(r_resp.status, 200)
                self.assertIn("text/html", r_resp.headers.get("Content-Type"))

    def test_sample_csv(self):
        req = urllib.request.Request(f"{self.base_url}/api/samples/csv")
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["format"], "CSV")
            self.assertEqual(data["aggregate_score"], 63.8)

    def test_upload_cyclonedx_file(self):
        sample_path = BASE_DIR / "data" / "sample_bom_cyclonedx.json"
        with open(sample_path, "rb") as f:
            content = f.read()

        req = urllib.request.Request(
            f"{self.base_url}/api/upload",
            data=content,
            headers={
                "Content-Type": "application/json",
                "X-Filename": "custom_upload.json",
                "X-Clean-Csv": "false",
            },
            method="POST",
        )
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)
            data = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(data["filename"], "custom_upload.json")
            self.assertEqual(data["format"], "CycloneDX JSON")
            self.assertEqual(data["aggregate_score"], 62.7)

    def test_upload_invalid_bom_rejected(self):
        invalid_json = json.dumps({"not_a_bom": True, "hello": "world"}).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base_url}/api/upload",
            data=invalid_json,
            headers={
                "Content-Type": "application/json",
                "X-Filename": "invalid.json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as resp:
                self.fail("Expected 400 Bad Request, but request succeeded")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)
            err_data = json.loads(e.read().decode("utf-8"))
            self.assertIn("error", err_data)
            self.assertIn("is not a CycloneDX BOM", err_data["error"])


if __name__ == "__main__":
    unittest.main()
