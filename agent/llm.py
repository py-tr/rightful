"""Vultr Serverless Inference client for the help-desk agent (OpenAI-compatible chat completions).

- Model ids are pinned in a list with fallbacks, because the catalogue can change during judging.
- Every run has a hard spending cap computed from token usage; reaching it stops the run (reported as "cap", never
  as a model result).
- The key comes from the control plane's environment. It never enters the sandbox: the agent's scripts run in the
  sandbox, but the model calls happen here, on the control plane.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

import httpx

BASE = "https://api.vultrinference.com/v1"
# USD per 1M tokens (input, output), as used for our measured runs (they matched Vultr's billed totals within cents).
# Unknown models are costed at a deliberately high rate so the cap errs on the safe side.
PRICES = {"glm-5.3": (0.75, 3.00), "glm-5.3-flash": (0.10, 0.35), "qwen3.8-27b": (0.15, 1.00),
          "deepseek-v4.1-flash-1017": (0.15, 0.60)}
DEFAULT_MODELS = ["glm-5.3-flash", "qwen3.8-27b", "deepseek-v4.1-flash-1017"]


class CapReached(RuntimeError):
    pass


@dataclass
class LLM:
    models: list[str] = field(default_factory=lambda: list(DEFAULT_MODELS))
    cap_usd: float = 0.25
    reasoning_effort: str | None = None
    max_tokens: int | None = None   # overrides chat()'s default; the demo raises it (11-05: the model spent all 3,000
                                    # tokens reasoning, finish_reason "length", and returned an empty reply)
    api_key: str | None = None
    http: httpx.Client | None = None
    spent: float = 0.0
    calls: int = 0
    used_model: str | None = None

    def __post_init__(self):
        self.api_key = self.api_key or os.environ.get("VULTR_INFERENCE_API_KEY")
        self.http = self.http or httpx.Client(base_url=BASE, timeout=120)

    def chat(self, messages: list[dict], tools: list[dict] | None = None, max_tokens: int = 3000) -> dict:
        if self.spent >= self.cap_usd:
            raise CapReached(f"spent ${self.spent:.4f} of the ${self.cap_usd} cap")
        last_err = None
        for model in self.models:
            body = {"model": model, "messages": messages, "max_tokens": self.max_tokens or max_tokens}
            if tools:
                body["tools"] = tools
            if self.reasoning_effort:
                body["reasoning_effort"] = self.reasoning_effort
            for attempt in range(3):
                r = self.http.post("/chat/completions", json=body,
                                   headers={"Authorization": f"Bearer {self.api_key}"})
                if r.status_code in (429, 500, 502, 503, 504):
                    last_err = f"HTTP {r.status_code}"
                    time.sleep(1.5 * (attempt + 1))
                    continue
                if r.status_code == 404:          # model left the catalogue: fall back to the next one
                    last_err = f"model {model} not available"
                    break
                r.raise_for_status()
                j = r.json()
                u = j.get("usage") or {}
                pin, pout = PRICES.get(model, (1.0, 4.0))
                self.spent += (u.get("prompt_tokens", 0) * pin + u.get("completion_tokens", 0) * pout) / 1e6
                self.calls += 1
                self.used_model = model
                return j
        raise RuntimeError(f"no model answered ({last_err})")
