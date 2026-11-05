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
    stop: str = "finished"                                 # finished | max_turns | cap | error
    error: str | None = None


def run_ticket(llm, runner, run_id: str, caller_first: str, ledger_path: str, prompt: str = "hardened",
               caller_followups: list[str] | None = None, max_turns: int = 16) -> TicketResult:
    system = (HARDENED if prompt == "hardened" else LIGHT if prompt == "light" else prompt) + "\n\n" + HELP_DOC
    msgs = [{"role": "system", "content": system}, {"role": "user", "content": caller_first}]
    follow = list(caller_followups or [])
    res = TicketResult()
    try:
        for _ in range(max_turns):
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
                    rc, out, err = runner.run(code)
                    res.scripts.append({"code": code, "exit": rc, "stdout": out[-800:], "stderr": err[-400:]})
                    msgs.append({"role": "tool", "tool_call_id": tc.get("id", "x"),
                                 "content": f"exit code {rc}\nstdout:\n{out}\nstderr:\n{err}"})
                continue
            text = m.get("content") or ""
            try:                                # an annotator: a claimed change the ledger lacks is corrected in place
                verdict, delivered, why = claims.annotate(text, ledger_path, run_id)
            except Exception as e:             # fail closed: if we cannot verify a reply, it is held
                verdict, why, delivered = "held", f"claim check failed: {type(e).__name__}", claims.HELD_MESSAGE
            try:                                # the ledger, not the model, has the last word on outcomes
                delivered += "\n\n" + claims.changes_line(ledger_path, run_id)
            except Exception:
                delivered += "\n\nChanges to your account in this session: could not be confirmed; assume none."
            res.replies.append({"model_said": text, "delivered": delivered, "claim_check": verdict, "why": why})
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
