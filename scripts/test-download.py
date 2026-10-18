#!/usr/bin/env python3
"""Exercise download retries and cache integrity against a local HTTP server."""

import hashlib
import tempfile
import threading
import unittest
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from download import download

PAYLOAD = b"verified installer contents\n" * 100
CHECKSUM = hashlib.sha256(PAYLOAD).hexdigest()
REQUESTS = Counter()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        REQUESTS[self.path] += 1
        first_request = REQUESTS[self.path] == 1

        if self.path == "/retry" and first_request:
            self.send_response(503)
            self.end_headers()
            self.wfile.write(b"temporarily unavailable")
            return

        self.send_response(200)
        self.send_header("Content-Length", str(len(PAYLOAD)))
        self.end_headers()

        if self.path == "/interrupted" and first_request:
            self.wfile.write(PAYLOAD[:10])
            self.close_connection = True
        else:
            self.wfile.write(PAYLOAD)

    def log_message(self, *_):
        pass


class DownloadTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.destination = Path(self.directory.name) / "installer.exe"

    def check_retry(self, route):
        download(self.url + route, self.destination, CHECKSUM)
        self.assertEqual(self.destination.read_bytes(), PAYLOAD)
        self.assertEqual(REQUESTS[route], 2)
        self.assertFalse(self.destination.with_suffix(".exe.partial").exists())

    def test_retries_service_unavailable(self):
        self.check_retry("/retry")

    def test_retries_interrupted_transfer(self):
        self.check_retry("/interrupted")

    def test_reuses_verified_cache_without_network(self):
        download(self.url + "/cached", self.destination, CHECKSUM)
        download(self.url + "/cached", self.destination, CHECKSUM)
        self.assertEqual(REQUESTS["/cached"], 1)

    def test_rejects_bad_download_and_removes_partial(self):
        with self.assertRaisesRegex(RuntimeError, "Checksum mismatch"):
            download(self.url + "/bad", self.destination, "0" * 64)
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.destination.with_suffix(".exe.partial").exists())

    def test_rejects_corrupt_cache_without_network(self):
        self.destination.write_bytes(b"corrupt")
        with self.assertRaisesRegex(RuntimeError, "Checksum mismatch"):
            download(self.url + "/unused", self.destination, CHECKSUM)
        self.assertEqual(REQUESTS["/unused"], 0)
        self.assertEqual(self.destination.read_bytes(), b"corrupt")


if __name__ == "__main__":
    unittest.main()
