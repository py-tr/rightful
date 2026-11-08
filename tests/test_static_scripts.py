"""Every page's inline script parses (11-08: a '//' comment on a one-line block blanked the share page)."""
import glob
import os
import re
import shutil
import subprocess

import pytest

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demo", "static")
PAGES = sorted(glob.glob(os.path.join(STATIC, "*.html")))


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
@pytest.mark.parametrize("page", PAGES, ids=[os.path.basename(p) for p in PAGES])
def test_inline_script_parses(page, tmp_path):
    src = open(page, encoding="utf-8").read()
    js = "\n".join(re.findall(r"<script>(.*?)</script>", src, re.S))
    if not js.strip():
        pytest.skip("no inline script")
    f = tmp_path / "page.js"
    f.write_text(js, encoding="utf-8")
    r = subprocess.run(["node", "--check", str(f)], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr[-600:]
