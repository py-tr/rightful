"""The edge proxy stamps the task's run id and drops any copy the sandbox sends."""
import importlib
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx

seen = []


class Upstream(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_PUT(self):
        n = int(self.headers.get("Content-Length") or 0)
        seen.append({"run": self.headers.get_all("X-Gate-Run"), "path": self.path, "body": self.rfile.read(n)})
        self.send_response(204)
        self.send_header("Content-Length", "0")
        self.end_headers()


def test_edge_stamps_the_run_and_strips_the_sandboxes_copy():
    up = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    threading.Thread(target=up.serve_forever, daemon=True).start()
    os.environ["RUN_ID"] = "task-42"
    os.environ["UPSTREAM"] = f"http://127.0.0.1:{up.server_address[1]}"
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sandbox"))
    edge = importlib.import_module("edge")
    srv = ThreadingHTTPServer(("127.0.0.1", 0), edge.Edge)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    r = httpx.put(f"http://127.0.0.1:{srv.server_address[1]}/admin/realms/corp/users/x/reset-password?a=1",
                  content=b'{"type":"password"}', headers={"X-Gate-Run": "someone-elses-run"})
    assert r.status_code == 204
    assert seen[-1]["run"] == ["task-42"]                  # only the edge's stamp; the forged one is gone
    assert seen[-1]["path"].endswith("/reset-password?a=1") and seen[-1]["body"] == b'{"type":"password"}'
    srv.shutdown()
    up.shutdown()
