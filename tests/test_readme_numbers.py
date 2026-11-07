"""The README's numbers must match their sources (council 9 / another entry's idea, 11-07): a README that drifts from
the results files is the first thing a careful judge catches. Checks README.md and, while it exists, README.draft.md."""
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = (ROOT / "eval" / "RESULTS-gateon.md").read_text(encoding="utf-8")
READMES = [p for p in (ROOT / "README.md", ROOT / "README.draft.md") if p.exists()]


@pytest.mark.parametrize("path", READMES, ids=lambda p: p.name)
def test_demo_rates_match_the_measured_values_the_page_shows(path):
    from demo.scenarios import SCENARIOS
    m = SCENARIOS["takeover"]["measured"]
    text = path.read_text(encoding="utf-8")
    for short, model in (("qwen", "qwen3.8-27b"), ("glm", "glm-5.3-flash"), ("deepseek", "deepseek-v4.1-flash-1017")):
        # both "qwen 34/40" and "fooled qwen3.8-27b in 34 of 40" (audit 11-07: the "of" form slipped through)
        for hit in re.finditer(rf"{short}\S*\s+(?:in\s+)?(\d+)(?:/| of )40", text):
            assert int(hit.group(1)) == m[model][0], f"{path.name}: {short} {hit.group(1)} of 40 but measured {m[model][0]}/40"


@pytest.mark.parametrize("path", READMES, ids=lambda p: p.name)
def test_headline_evaluation_numbers_come_from_the_results_file(path):
    text = path.read_text(encoding="utf-8")
    for n in ("1,199", "5,240"):
        if n in text:
            assert n.replace(",", "") in RESULTS.replace(",", ""), f"{path.name} quotes {n}, not found in RESULTS-gateon.md"
    for pct in re.findall(r"(\d+\.\d)%", text):
        assert pct + "%" in RESULTS or pct in RESULTS, f"{path.name} quotes {pct}%, not found in RESULTS-gateon.md"
