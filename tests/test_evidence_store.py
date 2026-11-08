"""The S3 signer must match the published SigV4 example exactly; the store must PUT with that signature and stay off
unless configured."""
import datetime as dt

import httpx

from gate.evidence_store import EvidenceStore, sigv4_headers

# Amazon S3 documentation, "Signature Calculations for the Authorization Header: Transferring Payload in a Single
# Chunk", example "GET Object": GET /test.txt, Range bytes=0-9, 20130524T000000Z, us-east-1, the documented example keys.
AK, SK = "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
WHEN = dt.datetime(2013, 5, 24, 0, 0, 0, tzinfo=dt.timezone.utc)


def test_sigv4_matches_the_s3_documentation_example():
    h = sigv4_headers("GET", "https://examplebucket.s3.amazonaws.com/test.txt", {"Range": "bytes=0-9"}, b"",
                      AK, SK, "us-east-1", "s3", now=WHEN)
    assert h["authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,"
        "SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"
        "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41")


def test_put_sends_a_signed_public_read_object():
    seen = {}

    def handler(req):
        seen.update(method=req.method, url=str(req.url), auth=req.headers.get("authorization", ""),
                    acl=req.headers.get("x-amz-acl"), body=req.content)
        return httpx.Response(200)
    store = EvidenceStore("https://fra1.vultrobjects.com", "rightful-evidence", "K", "S",
                          client=httpx.Client(transport=httpx.MockTransport(handler)))
    url = store.put("receipts/abc12345.json", b'{"ok":true}')
    assert url == "https://fra1.vultrobjects.com/rightful-evidence/receipts/abc12345.json"
    assert seen["method"] == "PUT" and seen["acl"] == "public-read" and seen["body"] == b'{"ok":true}'
    assert seen["auth"].startswith("AWS4-HMAC-SHA256 Credential=K/") and "x-amz-acl" in seen["auth"]


def test_the_store_is_off_unless_fully_configured(monkeypatch):
    for k in ("ENDPOINT", "BUCKET", "KEY", "SECRET"):
        monkeypatch.delenv(f"EVIDENCE_S3_{k}", raising=False)
    assert EvidenceStore.from_env() is None
    monkeypatch.setenv("EVIDENCE_S3_ENDPOINT", "https://fra1.vultrobjects.com")
    monkeypatch.setenv("EVIDENCE_S3_BUCKET", "b")
    assert EvidenceStore.from_env() is None                    # key and secret still missing
