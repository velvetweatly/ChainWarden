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
