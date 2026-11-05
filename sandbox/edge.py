"""Edge proxy: the ONLY way out of a task's private network, and it leads only to the broker.

It is created by the control plane for one task. It stamps that task's run id on every request (X-Gate-Run) and
drops any copy the sandbox sent, so a sandbox cannot speak for another run. It forwards method, path, query and body
to the broker and nothing anywhere else. It holds no credential.
"""
import http.client
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

RUN_ID = os.environ["RUN_ID"]
UP = urlsplit(os.environ["UPSTREAM"])          # e.g. http://host.docker.internal:8090
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "upgrade", "proxy-authorization", "proxy-authenticate",
       "trailer", "host", "x-gate-run", "content-length"}


class Edge(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _go(self):
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n) if n else None
        headers = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        headers["X-Gate-Run"] = RUN_ID                       # set by us, never by the sandbox
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
