"""Test 8/9 — HTTP API + SSE integration against a real server instance
(binds an ephemeral port, exercises REST endpoints, action validation and the
live event stream — end-to-end without any browser)."""
import json
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request

from tests import REPO_ROOT  # noqa: F401
from hashflow.server import make_server
from hashflow.simulator import SimulatorFleet


class TestServerApi(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        socket.setdefaulttimeout(5)
        cls.model = SimulatorFleet(n_devices=8, seed=42)
        cls.server = make_server("127.0.0.1", 0, cls.model)  # ephemeral port
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        time.sleep(0.2)

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()

    def _get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}") as r:
            return r.status, json.loads(r.read().decode())

    def _post(self, path, body):
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}{path}",
            data=json.dumps(body).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req) as r:
                return r.status, json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read().decode())

    def test_health(self):
        status, data = self._get("/api/health")
        self.assertEqual(status, 200)
        self.assertEqual(data["status"], "ok")
        self.assertIn("version", data)

    def test_fleet_endpoint_shape(self):
        status, fleet = self._get("/api/fleet")
        self.assertEqual(status, 200)
        self.assertEqual(len(fleet), 8)
        for key in ("id", "name", "zone", "status", "hashrate", "temp_c", "health"):
            self.assertIn(key, fleet[0])

    def test_metrics_endpoint(self):
        status, m = self._get("/api/metrics")
        self.assertEqual(status, 200)
        self.assertGreaterEqual(m["total_workers"], m["active_workers"])
        self.assertIn("acceptance_pct", m)

    def test_series_and_executive_and_risk(self):
        s_status, series = self._get("/api/series")
        self.assertEqual(s_status, 200)
        self.assertIn("hashrate", series)
        e_status, exe = self._get("/api/executive")
        self.assertEqual(e_status, 200)
        self.assertIn("xmr_per_day", exe)
        r_status, risks = self._get("/api/risk")
        self.assertEqual(r_status, 200)
        self.assertTrue(all({"name", "likelihood", "impact"} <= set(x) for x in risks))

    def test_alert_ack_flow(self):
        _, snap = self._get("/api/snapshot")
        if snap["alerts"]:
            aid = snap["alerts"][-1]["id"]
            status, data = self._post("/api/alerts/ack", {"id": aid})
            self.assertEqual(status, 200)
            self.assertTrue(data["ok"])

    def test_emergency_stop_requires_confirm_token(self):
        status, data = self._post("/api/actions/emergency-stop", {"confirm": "nope"})
        self.assertEqual(status, 400)
        self.assertIn("STOP", data["error"])
        status, data = self._post("/api/actions/emergency-stop", {"confirm": "STOP"})
        self.assertEqual(status, 200)
        self.assertTrue(data["ok"])

    def test_unknown_endpoint_404(self):
        status, data = self._post("/api/actions/launch-rocket", {})
        self.assertEqual(status, 404)

    def test_sse_stream_delivers_snapshot_and_ticks(self):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/stream")
        with urllib.request.urlopen(req, timeout=8) as r:
            self.assertEqual(r.status, 200)
            self.assertEqual(r.headers.get("Content-Type"), "text/event-stream")
            buf = b""
            deadline = time.time() + 8
            while time.time() < deadline:
                buf += r.read(256)
                # wait for the COMPLETE first snapshot event (header + body)
                if b"event: snapshot" in buf and b"\n\n" in buf.split(b"event: snapshot", 1)[1]:
                    break
            self.assertIn(b"event: snapshot", buf)
            self.assertIn(b"data: {", buf)
            # parse the first snapshot payload
            first = buf.split(b"event: snapshot", 1)[1].split(b"\n\n")[0]
            payload = json.loads(first.split(b"data: ", 1)[1])
            self.assertIn("metrics", payload)
            self.assertIn("fleet", payload)

    def test_static_index_served(self):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/") as r:
            body = r.read().decode()
        self.assertEqual(r.status, 200)
        self.assertIn("Hashflow", body)

    def test_path_traversal_blocked(self):
        try:
            with urllib.request.urlopen(
                    f"http://127.0.0.1:{self.port}/../hashflow/server.py") as r:
                self.assertNotEqual(r.status, 200)
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 404)


if __name__ == "__main__":
    unittest.main()
