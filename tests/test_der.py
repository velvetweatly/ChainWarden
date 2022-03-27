import unittest

from chainwarden import der


class TestDER(unittest.TestCase):
    def test_read_short_length_tlv(self):
        # INTEGER 0x2A, length 1.
        tlv = der.read_tlv(bytes([0x02, 0x01, 0x2A]))
        self.assertEqual(tlv.tag, der.TAG_INTEGER)
        self.assertEqual(tlv.length, 1)
