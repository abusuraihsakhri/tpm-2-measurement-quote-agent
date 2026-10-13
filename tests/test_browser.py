"""Static browser-demo checks; no network access is required."""
from pathlib import Path
import re
import shutil
import subprocess

import pytest


WEB = Path(__file__).resolve().parents[1] / "web" / "index.html"


def test_browser_demo_is_standalone_and_has_no_fake_fallback():
    html = WEB.read_text(encoding="utf-8")
    assert "<title>TPM 2.0 Measurement" in html
    assert 'crypto.subtle.sign(' in html
    assert 'crypto.subtle.verify(' in html
    assert "This is not hardware attestation." in html
    assert 'fetch("/api/' not in html
    assert "HMAC_SHA256_e83f9a72b941d6c381f9" not in html
    assert "<script" in html


def test_inline_browser_script_has_valid_javascript_syntax():
    node = shutil.which("node")
    if node is None:
        pytest.skip("Node.js not installed")
    html = WEB.read_text(encoding="utf-8")
    match = re.search(r"<script>(.*?)</script>", html, re.DOTALL)
    assert match
    completed = subprocess.run(
        [node, "--check", "-"],
        input=match.group(1),
        text=True,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stderr
