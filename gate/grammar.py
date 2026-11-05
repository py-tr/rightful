"""Strict request grammar: a raw HTTP request becomes one exact operation from the policy pack, or it is rejected.

The broker does not match paths loosely; it parses. Anything the grammar does not recognise is denied. This is
where encoded paths, ';' matrix parameters, '..', '//', trailing slashes, case tricks and unexpected body fields die.
(Found on Keycloak 26: PUT users/<id>;x=y/reset-password is accepted and acts on <id>.)
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .canon import CanonError, canonical_json, parse_json, request_hash

UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
PATH_CHARS = re.compile(r"^[A-Za-z0-9/_.-]+$")  # no '%', ';', '?', '#', '\\', spaces or non-ASCII
OVERRIDE_PLACEHOLDER = "<broker-supplied>"


class Reject(Exception):
    """The request is not an operation of this pack. `kind` is 'malformed' or 'not_allowlisted'."""

    def __init__(self, kind: str, reason: str):
        super().__init__(f"{kind}: {reason}")
        self.kind, self.reason = kind, reason


@dataclass(frozen=True)
class Operation:
    name: str                      # pack operation name, or "read" / "static"
    kind: str                      # "read" | "static" | "write" | "composite"
    method: str
    path: str
    query: tuple[tuple[str, str], ...]
    params: dict[str, str]         # template parameters, e.g. {"user": "<uuid>"}
    body: Any                      # parsed body with override fields as the placeholder
    canonical_body: bytes
    request_hash: str
    receipt: str | None = None     # approver kind: "owner" | "manager" | "contact"
    label: str | None = None       # short name for the binding message
    overrides: dict[str, str] = field(default_factory=dict)  # field -> override kind

    @property
    def user(self) -> str | None:
        return self.params.get("user")


def _check_path(path: str, allow_trailing_slash: bool = False) -> None:
    if not path.startswith("/"):
        raise Reject("malformed", "path must start with '/'")
    if not PATH_CHARS.match(path):
        raise Reject("malformed", "path contains a forbidden character (only A-Z a-z 0-9 / _ . - allowed)")
    if "//" in path:
        raise Reject("malformed", "empty path segment")
    if path.endswith("/") and path != "/" and not allow_trailing_slash:
        raise Reject("malformed", "trailing slash")
    segs = path.split("/")[1:]
    if any(s in (".", "..") for s in segs):
        raise Reject("malformed", "dot segment in path")


PCT = re.compile(r"%([0-9A-Fa-f]{2})")


def _decode_read_value(v: str) -> str:
    """Reads may carry a URL-encoded search value ('Jordan%20Avery', 'Jordan+Avery'). Decode exactly once; refuse
    anything that decodes to another escape (double encoding) or to a control character. The decoded value is then
    checked against the pack's read-value pattern."""
    v = v.replace("+", " ")
    if "%" in PCT.sub("", v):
        raise Reject("malformed", "broken percent-encoding in the query")
    out = PCT.sub(lambda m: chr(int(m.group(1), 16)), v)
    if "%" in out or any(ord(ch) < 32 or ord(ch) > 126 for ch in out):
        raise Reject("malformed", "double-encoded or control characters in the query")
    return out


def _split_target(target: str, decode_values: bool = False) -> tuple[str, list[tuple[str, str]]]:
    if "#" in target:
        raise Reject("malformed", "fragment in request target")
    path, _, qs = target.partition("?")
    query: list[tuple[str, str]] = []
    if qs:
        for part in qs.split("&"):
            if not part or "=" not in part:
                raise Reject("malformed", "query parameter without a value")
            k, v = part.split("=", 1)
            if "%" in k or "+" in k:
                raise Reject("malformed", "encoded characters in a query key are not accepted")
            if decode_values:
                v = _decode_read_value(v)
            elif "%" in v or "+" in v:
                raise Reject("malformed", "encoded characters in the query are not accepted")
            query.append((k, v))
        keys = [k for k, _ in query]
        if len(keys) != len(set(keys)):
            raise Reject("malformed", "repeated query parameter")
    return path, query


def _match(template: str, path: str, realm: str) -> dict[str, str] | None:
    t, p = template.split("/"), path.split("/")
    if len(t) != len(p):
        return None
    params: dict[str, str] = {}
    for ts, ps in zip(t, p):
        if ts.startswith("{") and ts.endswith("}"):
            name = ts[1:-1]
            if name == "realm":
                if ps != realm:
                    return None
            elif not UUID_RE.match(ps):
                return None
            params[name] = ps
        elif ts != ps:
            return None
    return params


def _check_body(spec: dict, value: Any) -> tuple[Any, dict[str, str]]:
    kind = spec["type"]
    if kind == "none":
        if value is not None:
            raise Reject("not_allowlisted", "this operation takes no body")
        return None, {}
    if kind == "array_enum":
        allowed = spec["enum"]
        if not isinstance(value, list) or not value or len(value) != len(set(map(str, value))) \
                or any(v not in allowed for v in value):
            raise Reject("not_allowlisted", f"body must be a non-empty list of distinct values from {allowed}")
        return value, {}
    if kind == "object":
        fields = spec["fields"]
        if not isinstance(value, dict):
            raise Reject("not_allowlisted", "body must be a JSON object")
        extra = sorted(set(value) - set(fields))
        if extra:
            raise Reject("not_allowlisted", f"unexpected body field(s) {extra}")
        out, overrides = {}, {}
        for name, f in fields.items():
            if name not in value:
                if f.get("required"):
                    raise Reject("not_allowlisted", f"missing required field {name!r}")
                continue
            v = value[name]
            if "enum" in f and v not in f["enum"]:
                raise Reject("not_allowlisted", f"field {name!r} must be one of {f['enum']}")
            if f.get("type") == "string":
                if not isinstance(v, str):
                    raise Reject("not_allowlisted", f"field {name!r} must be a string")
                if "regex" in f and not re.match(f["regex"], v):
                    raise Reject("not_allowlisted", f"field {name!r} has an unexpected format")
            if "override" in f:
                overrides[name] = f["override"]
                v = OVERRIDE_PLACEHOLDER
            out[name] = v
        for name, f in fields.items():  # override fields are always present in what the broker forwards
            if "override" in f and name not in out:
                out[name] = OVERRIDE_PLACEHOLDER
                overrides[name] = f["override"]
        return out, overrides
    raise ValueError(f"unknown body type {kind!r} in pack")


def parse(pack: dict, method: str, target: str, body: bytes) -> Operation:
    """Parse one request against the pack, or raise Reject."""
    method = method.upper()
    if method not in ("GET", "PUT", "POST", "DELETE"):
        raise Reject("not_allowlisted", f"method {method} is not used by this pack")
    realm = pack["realm"]
    raw_path = target.partition("?")[0]
    if method == "GET" and not raw_path.startswith("/admin/realms/") \
            and any(raw_path.startswith(p) for p in pack["static_get_prefixes"]):
        # Console assets and the browser's sign-in routes: never the admin API. Path still strictly checked;
        # the query is opaque here (these routes carry encoded redirect URIs) and is not forwarded to /admin/.
        _check_path(raw_path, allow_trailing_slash=True)
        if body:
            raise Reject("malformed", "GET with a body")
        return Operation("static", "static", method, raw_path, (), {}, None, b"",
                         request_hash(method, raw_path, [], b""))
    path, query = _split_target(target, decode_values=(method == "GET"))   # reads only; writes stay strict
    _check_path(path)

    if method == "GET":
        if body:
            raise Reject("malformed", "GET with a body")
        rq = pack["read_query"]
        for k, v in query:
            if k in rq.get("empty_only", []) and v == "":
                continue            # the console always sends e.g. `q=`; a value (an attribute search) is refused
            if k not in rq["keys"] or not re.match(rq["value_regex"], v):
                raise Reject("not_allowlisted", f"read query parameter {k!r} not allowed")
        for tpl in pack["reads"]:
            params = _match(tpl, path, realm)
            if params is not None:
                return Operation("read", "read", method, path, tuple(query), params, None, b"",
                                 request_hash(method, path, query, b""))
        raise Reject("not_allowlisted", "GET path is not in the read allowlist")

    for name, op in pack.get("composites", {}).items():
        # A named, pre-declared set of steps that the BROKER executes after one approval. The agent only names it.
        if op["method"] != method:
            continue
        params = _match(op["path"], path, realm)
        if params is None:
            continue
        if query:
            raise Reject("not_allowlisted", f"{name} takes no query parameters")
        if body:
            raise Reject("not_allowlisted", f"{name} takes no body (the broker decides every parameter)")
        return Operation(name, "composite", method, path, (), params, None, b"",
                         request_hash(method, path, [], b""), op["receipt"], op["label"])

    for name, op in pack["writes"].items():
        if op["method"] != method:
            continue
        params = _match(op["path"], path, realm)
        if params is None:
            continue
        allowed_q = op.get("query", {})
        for k, v in query:
            if k not in allowed_q or not re.match(allowed_q[k], v):
                raise Reject("not_allowlisted", f"query parameter {k!r} not allowed for {name}")
        try:
            parsed = parse_json(body)
        except CanonError as e:
            raise Reject("malformed", str(e)) from e
        clean, overrides = _check_body(op["body"], parsed)
        cbody = canonical_json(clean)
        return Operation(name, "write", method, path, tuple(query), params, clean, cbody,
                         request_hash(method, path, query, cbody), op["receipt"], op["label"], overrides)
    raise Reject("not_allowlisted", f"{method} {path} is not an operation of pack {pack['pack']!r}")
