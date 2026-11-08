"""The MCP server is the same gate with a different front door: it holds no credential, a change is refused with a
challenge until the approver approves, and nothing reaches the identity server before that (brainstorm P2, 11-08)."""
import asyncio
import json
import pathlib

import pytest

pytest.importorskip("mcp")

from tests.test_eval_modes import U, make  # the in-process gate + fake Keycloak used by the other gate tests


def _call(server, name, args):
    out = asyncio.run(server.call_tool(name, args))
    blocks = out[0] if isinstance(out, tuple) else out
    if isinstance(blocks, dict):
        return blocks.get("result", blocks)
    text = blocks[0].text
    try:
        return json.loads(text)
    except ValueError:                                  # a tool that returns a plain string
        return text


@pytest.fixture()
def server(tmp_path, monkeypatch):
    from agent import mcp_server
    c, writes, gate = make(tmp_path, "corp")
    c.app.state.open_run("run-1", "full")
    c.headers.update({"X-Gate-Run": "run-1"})
    monkeypatch.setattr(mcp_server.hd, "REALM", "corp")
    mcp_server.hd.use_client(c)
    yield mcp_server.mcp, writes
    mcp_server.hd.use_client(None)


def test_the_tools_are_the_help_desk_operations(server):
    mcp, _ = server
    names = {t.name for t in asyncio.run(mcp.list_tools())}
    assert {"find_user", "lock_status", "reset_password", "change_email", "send_challenge",
            "wait_for_approval", "escalate"} <= names


def test_a_change_through_mcp_is_refused_with_a_challenge_and_writes_nothing(server):
    mcp, writes = server
    r = _call(mcp, "reset_password", {"user_id": U})
    assert r["ok"] is False and r["outcome"] == "denied_no_receipt", r
    assert r["challenge_required"]["challenge"] and r["challenge_required"]["approver"] == "owner"
    assert not any("reset-password" in p for _, p, _ in writes)       # nothing reached the identity server


def test_after_the_owner_approves_the_same_change_goes_through_once(server):
    """The fake identity server approves every push, so this is the honest path end to end, through MCP."""
    mcp, writes = server
    cid = _call(mcp, "reset_password", {"user_id": U})["challenge_required"]["challenge"]
    _call(mcp, "send_challenge", {"challenge_id": cid})
    assert _call(mcp, "wait_for_approval", {"challenge_id": cid, "timeout_s": 5}) == "approved"
    assert _call(mcp, "reset_password", {"user_id": U})["ok"] is True
    assert sum("reset-password" in p for _, p, _ in writes) == 1         # exactly one change, after the approval
    again = _call(mcp, "reset_password", {"user_id": U})                 # the approval was used once
    assert again["ok"] is False
    assert sum("reset-password" in p for _, p, _ in writes) == 1


def test_the_server_holds_no_credential():
    src = pathlib.Path("agent/mcp_server.py").read_text(encoding="utf-8")
    for needle in ("client_secret", "Authorization", "Bearer", "password="):
        assert needle not in src
