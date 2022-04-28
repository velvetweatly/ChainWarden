import base64
import unittest

from chainwarden import pemread


def _wrap(label: str, data: bytes) -> str:
    b64 = base64.b64encode(data).decode("ascii")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return f"-----BEGIN {label}-----\n" + "\n".join(lines) + f"\n-----END {label}-----\n"


class TestPEMRead(unittest.TestCase):
    def test_single_block(self):
        text = _wrap("CERTIFICATE", b"\x30\x03\x02\x01\x05")
        blocks = pemread.split_blocks(text)
        self.assertEqual(len(blocks), 1)
