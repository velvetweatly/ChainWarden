import base64
import unittest

from chainwarden import pemread


def _wrap(label: str, data: bytes) -> str:
    b64 = base64.b64encode(data).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
