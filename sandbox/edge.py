"""Edge proxy: the ONLY way out of a task's private network, and it leads only to the broker.

It is created by the control plane for one task. It stamps that task's run id on every request (X-Gate-Run) and
drops any copy the sandbox sent, so a sandbox cannot speak for another run. It signs each request with this task's
key (RUN_KEY, derived by the control plane for this run only), so nothing else on the network can claim the run.
It forwards method, path, query and body to the broker and nothing anywhere else. It holds no identity credential.
"""
import hashlib
import hmac
import http.client
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

RUN_ID = os.environ["RUN_ID"]
RUN_KEY = os.environ.get("RUN_KEY", "")
UP = urlsplit(os.environ["UPSTREAM"])          # e.g. http://host.docker.internal:8090
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "upgrade", "proxy-authorization", "proxy-authenticate",
       "trailer", "host", "x-gate-run", "x-gate-ts", "x-gate-sig", "content-length"}


def sign(key_hex: str, run_id: str, ts: str, method: str, target: str, body: bytes) -> str:
    """Same as broker/runkey.py:sign (a test checks they agree)."""
    msg = "\n".join((run_id, ts, method.upper(), target, hashlib.sha256(body or b"").hexdigest())).encode()
    return hmac.new(bytes.fromhex(key_hex), msg, hashlib.sha256).hexdigest()


class Edge(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _go(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        headers["X-Gate-Run"] = RUN_ID                       # set by us, never by the sandbox
        if RUN_KEY:
            ts = str(int(time.time()))
            headers["X-Gate-Ts"] = ts
            headers["X-Gate-Sig"] = sign(RUN_KEY, RUN_ID, ts, self.command, self.path, body or b"")
        try:
            c = http.client.HTTPConnection(UP.hostname, UP.port or 80, timeout=150)
            c.request(self.command, self.path, body=body, headers=headers)
            r = c.getresponse()
            data = r.read()
        except OSError as e:
            data = f'{{"error": "broker unreachable: {type(e).__name__}"}}'.encode()
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        self.send_response(r.status)
        for k, v in r.getheaders():
            if k.lower() not in HOP:
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    do_GET = do_PUT = do_POST = do_DELETE = do_PATCH = do_HEAD = do_OPTIONS = _go


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Edge).serve_forever()
