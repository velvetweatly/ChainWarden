import io
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from chainwarden import cli

SAMPLES = str(Path(__file__).resolve().parent.parent / "samples")


