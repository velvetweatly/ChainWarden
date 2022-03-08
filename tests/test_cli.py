import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from chainwarden import cli

SAMPLES = str(Path(__file__).resolve().parent.parent / "samples")


def _run(argv):
    buf = io.StringIO()
    with redirect_stdout(buf):
        code = cli.main(argv)
    return code, buf.getvalue()


class TestCLI(unittest.TestCase):
    def test_version_exit_zero(self):
        code, out = _run(["version"])
        self.assertEqual(code, 0)
        self.assertIn("chainwarden", out)

    def test_audit_returns_one_when_findings(self):
        code, out = _run(["audit", SAMPLES, "--as-of", "2026-09-02"])
        self.assertEqual(code, 1)
