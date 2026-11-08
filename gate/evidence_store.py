"""Publish evidence to Vultr Object Storage (S3-compatible), outside the demo server.

Every signed run receipt (gate/receipt_sign.py) and each conversation's ledger head are written to a bucket, so a
reviewer can fetch them from a public URL the demo server alone cannot quietly rewrite after the fact: the ledger's
truncation check (gate/ledger.py: verify(expected_head=...)) finally has an anchor kept elsewhere.

Off unless all of EVIDENCE_S3_ENDPOINT, EVIDENCE_S3_BUCKET, EVIDENCE_S3_KEY and EVIDENCE_S3_SECRET are set. Uses only
httpx and AWS Signature Version 4 (no extra dependency); the signer is tested against the S3 documentation's example.
Uploads never block or fail a conversation: errors are counted and logged, and the page simply omits the link.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import hmac
import os
import threading
from urllib.parse import quote, urlsplit

import httpx


def _h(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def _hm(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def sigv4_headers(method: str, url: str, headers: dict, payload: bytes, access_key: str, secret_key: str,
                  region: str = "us-east-1", service: str = "s3", now: _dt.datetime | None = None) -> dict:
    """Return the headers (incl. Authorization) for an AWS SigV4-signed request. `headers` may hold extra headers to
    sign (e.g. Range, Content-Type, x-amz-acl); host, x-amz-date and x-amz-content-sha256 are added here."""
    now = now or _dt.datetime.now(_dt.timezone.utc)
    amz_date, day = now.strftime("%Y%m%dT%H%M%SZ"), now.strftime("%Y%m%d")
    u = urlsplit(url)
    payload_hash = _h(payload)
    hdrs = {k.lower(): str(v).strip() for k, v in headers.items()}
    hdrs.update({"host": u.netloc, "x-amz-date": amz_date, "x-amz-content-sha256": payload_hash})
    signed = sorted(hdrs)
    canonical_uri = quote(u.path or "/", safe="/-_.~")
    q = sorted((k, v) for k, _, v in (p.partition("=") for p in u.query.split("&") if p))
    canonical_query = "&".join(f"{quote(k, safe='-_.~')}={quote(v, safe='-_.~')}" for k, v in q)
    canonical = "\n".join([method.upper(), canonical_uri, canonical_query,
                           "".join(f"{k}:{hdrs[k]}\n" for k in signed), ";".join(signed), payload_hash])
    scope = f"{day}/{region}/{service}/aws4_request"
    to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, _h(canonical.encode("utf-8"))])
    k = _hm(_hm(_hm(_hm(("AWS4" + secret_key).encode("utf-8"), day), region), service), "aws4_request")
    sig = hmac.new(k, to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    out = {k2: v for k2, v in hdrs.items() if k2 != "host"}
    out["authorization"] = (f"AWS4-HMAC-SHA256 Credential={access_key}/{scope},SignedHeaders={';'.join(signed)},"
                            f"Signature={sig}")
    return out


class EvidenceStore:
    def __init__(self, endpoint: str, bucket: str, access_key: str, secret_key: str, region: str = "us-east-1",
                 client: httpx.Client | None = None):
        self.base = endpoint.rstrip("/")
        self.bucket, self.ak, self.sk, self.region = bucket, access_key, secret_key, region
        self.http = client or httpx.Client(timeout=15)
        self.failures = 0

    @classmethod
    def from_env(cls) -> "EvidenceStore | None":
        e = {k: os.environ.get(f"EVIDENCE_S3_{k}") for k in ("ENDPOINT", "BUCKET", "KEY", "SECRET")}
        if not all(e.values()):
            return None
        return cls(e["ENDPOINT"], e["BUCKET"], e["KEY"], e["SECRET"], os.environ.get("EVIDENCE_S3_REGION", "us-east-1"))

    def public_url(self, key: str) -> str:
        return f"{self.base}/{self.bucket}/{quote(key, safe='/-_.~')}"

    def put(self, key: str, body: bytes, content_type: str = "application/json") -> str:
        url = self.public_url(key)
        hdrs = sigv4_headers("PUT", url, {"content-type": content_type, "x-amz-acl": "public-read"}, body,
                             self.ak, self.sk, self.region)
        r = self.http.put(url, content=body, headers=hdrs)
        r.raise_for_status()
        return url

    def put_async(self, key: str, body: bytes, on_done=None) -> None:
        """Fire and forget: a failure is counted, never raised into the conversation."""
        def run():
            try:
                url = self.put(key, body)
                if on_done:
                    on_done(url)
            except Exception:                         # noqa: BLE001
                self.failures += 1
        threading.Thread(target=run, daemon=True).start()
