"""The README's numbers must match their sources (council 9 / another entry's idea, 11-07): a README that drifts from
the results files is the first thing a careful judge catches. Checks README.md and, while it exists, README.draft.md."""
import pathlib
import re

import pytest

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = (ROOT / "eval" / "RESULTS-gateon.md").read_text(encoding="utf-8")
# 11-08: the README also quotes the pre-registered re-runs (honest completion, Vultr re-runs); every percentage must be
# found in SOME published results file, so a typo or an invented figure still fails
ALL_RESULTS = "\n".join(p.read_text(encoding="utf-8") for p in sorted((ROOT / "eval").glob("RESULTS*.md")))
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


def _found_fixed_rows() -> int:
    """Rows of EVIDENCE.md section 7 ("Found, fixed, tested"): one row is one counted problem (mentor 11-08)."""
    text = (ROOT / "docs" / "EVIDENCE.md").read_text(encoding="utf-8")
    section = text.split("## 7. Found, fixed, tested", 1)[1].split("\n## ", 1)[0]
    return sum(1 for line in section.splitlines()
               if line.startswith("|") and not line.startswith("|---") and not line.startswith("| Found |"))


@pytest.mark.parametrize("path", READMES, ids=lambda p: p.name)
def test_problem_count_matches_the_found_fixed_table(path):
    text = path.read_text(encoding="utf-8")
    for hit in re.finditer(r"(\d+) problems found", text):
        assert int(hit.group(1)) == _found_fixed_rows(), \
            f"{path.name} says {hit.group(1)} problems found; EVIDENCE.md section 7 has {_found_fixed_rows()} rows"


def test_no_placeholder_survives_in_the_readme():
    """A TODO (the video link, the hero image) must never reach the submitted README (mentor 11-08)."""
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "TODO" not in text, "README.md still contains a TODO placeholder"


@pytest.mark.parametrize("path", READMES, ids=lambda p: p.name)
def test_headline_evaluation_numbers_come_from_the_results_file(path):
    text = path.read_text(encoding="utf-8")
    for n in ("1,199", "5,240"):
        if n in text:
            assert n.replace(",", "") in RESULTS.replace(",", ""), f"{path.name} quotes {n}, not found in RESULTS-gateon.md"
    for pct in re.findall(r"(\d+\.\d)%", text):
        assert pct + "%" in ALL_RESULTS or pct in ALL_RESULTS, f"{path.name} quotes {pct}%, not found in any eval/RESULTS*.md"
