import unittest

from chainwarden import der


class TestDER(unittest.TestCase):
    def test_read_short_length_tlv(self):
        # INTEGER 0x2A, length 1.
        tlv = der.read_tlv(bytes([0x02, 0x01, 0x2A]))
        self.assertEqual(tlv.tag, der.TAG_INTEGER)
        self.assertEqual(tlv.length, 1)
        self.assertEqual(tlv.value, b"\x2a")
        self.assertEqual(tlv.end, 3)

    def test_read_long_length_tlv(self):
        # OCTET STRING with two byte length 0x0102 = 258 bytes.
        payload = b"\x00" * 258
        buf = bytes([0x04, 0x82, 0x01, 0x02]) + payload
        tlv = der.read_tlv(buf)
        self.assertEqual(tlv.length, 258)
        self.assertEqual(len(tlv.value), 258)

    def test_indefinite_length_rejected(self):
        with self.assertRaises(der.DERError):
            der.read_tlv(bytes([0x30, 0x80]))

    def test_value_past_end_rejected(self):
        with self.assertRaises(der.DERError):
            der.read_tlv(bytes([0x02, 0x05, 0x01]))

    def test_read_children(self):
        # SEQUENCE { INTEGER 1, INTEGER 2 }
        buf = bytes([0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02])
        seq = der.read_tlv(buf)
        kids = der.read_children(seq, buf)
        self.assertEqual(len(kids), 2)
        self.assertEqual(der.decode_integer(kids[0].value), 1)
        self.assertEqual(der.decode_integer(kids[1].value), 2)

    def test_decode_oid_rsa_encryption(self):
        # 1.2.840.113549.1.1.1 encoded.
        content = bytes([0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01])
