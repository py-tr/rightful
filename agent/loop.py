"""One help-desk ticket: caller -> model -> script in the sandbox -> real output -> model -> reply (Pattern A, with
errors fed back). The model's reply to the caller passes the claimed-vs-actual check before it is delivered."""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import claims
from .llm import CapReached
from .prompts import HARDENED, HELP_DOC, LIGHT

RUN_TOOL = [{"type": "function", "function": {
    "name": "run_python", "description": "Run a Python script in the sandbox. `import helpdesk` is available.",
    "parameters": {"type": "object", "properties": {"code": {"type": "string"}}, "required": ["code"]}}}]


@dataclass
class TicketResult:
    replies: list[dict] = field(default_factory=list)      # what the caller actually received
    scripts: list[dict] = field(default_factory=list)      # what the agent ran, with exit codes
    transcript: list[dict] = field(default_factory=list)
    empty_turns: list[dict] = field(default_factory=list)  # replies with no text: what the message held instead
    stop: str = "finished"                                 # finished | max_turns | cap | error
    error: str | None = None


def run_ticket(llm, runner, run_id: str, caller_first: str, ledger_path: str, prompt: str = "hardened",
               caller_followups: list[str] | None = None, max_turns: int = 16, help_doc: str = HELP_DOC,
               on_reply=None, history: list[dict] | None = None, on_event=None) -> TicketResult:
    """on_reply(delivered_text) -> next caller message or None: lets a scripted caller react (evaluation).
    history: earlier turns placed before the caller's message (the evaluation's forged-history cases).
    on_event(kind, data): live progress for the demo page: 'thinking', 'tool_call' {code}, 'tool_result'
    {exit, stdout, stderr}, 'reply' {model_said, delivered, verdict, changes_line}."""
    emit = on_event or (lambda kind, data: None)
    system = (HARDENED if prompt == "hardened" else LIGHT if prompt == "light" else prompt) + "\n\n" + help_doc
    msgs = [{"role": "system", "content": system}, *(history or []), {"role": "user", "content": caller_first}]
    follow = list(caller_followups or [])
    res = TicketResult()
    try:
        for _ in range(max_turns):
            emit("thinking", {})
            r = llm.chat(msgs, tools=RUN_TOOL)
            m = r["choices"][0]["message"]
            msgs.append({k: v for k, v in m.items() if k in ("role", "content", "tool_calls")})
            calls = m.get("tool_calls") or []
            if calls:
                for tc in calls:
                    try:
                        code = json.loads(tc["function"].get("arguments") or "{}").get("code", "")
                    except json.JSONDecodeError:
                        code = ""
                    emit("tool_call", {"code": code})
                    rc, out, err = runner.run(code)
                    emit("tool_result", {"exit": rc, "stdout": out[-1500:], "stderr": err[-600:]})
                    res.scripts.append({"code": code, "exit": rc, "stdout": out[-800:], "stderr": err[-400:]})
                    msgs.append({"role": "tool", "tool_call_id": tc.get("id", "x"),
                                 "content": f"exit code {rc}\nstdout:\n{out}\nstderr:\n{err}"})
                continue
            text = m.get("content") or ""
            if not text.strip():                # diagnosis: what an empty turn carried instead (keys, finish reason)
                res.empty_turns.append({"keys": sorted(m), "finish": r["choices"][0].get("finish_reason"),
                                        "reasoning_chars": len(m.get("reasoning_content") or m.get("reasoning") or "")})
            try:                                # an annotator: a claimed change the ledger lacks is corrected in place
                verdict, delivered, why = claims.annotate(text, ledger_path, run_id)
            except Exception as e:             # fail closed: if we cannot verify a reply, it is held
                verdict, why, delivered = "held", f"claim check failed: {type(e).__name__}", claims.HELD_MESSAGE
            try:                                # the ledger, not the model, has the last word on outcomes
                line = claims.changes_line(ledger_path, run_id)
            except Exception:
                line = "Changes to your account in this session: could not be confirmed; assume none."
            emit("reply", {"model_said": text, "delivered": delivered, "verdict": verdict, "changes_line": line})
            delivered += "\n\n" + line
            res.replies.append({"model_said": text, "delivered": delivered, "claim_check": verdict, "why": why})
            nxt = on_reply(delivered) if on_reply else None
            if nxt:
                msgs.append({"role": "user", "content": nxt})
                continue
            if follow:
                msgs.append({"role": "user", "content": follow.pop(0)})
                continue
            break
        else:
            res.stop = "max_turns"
    except CapReached as e:
        res.stop, res.error = "cap", str(e)
    except Exception as e:                     # an API or harness error is never a model result
        res.stop, res.error = "error", f"{type(e).__name__}: {e}"[:300]
    res.transcript = msgs
    return res
