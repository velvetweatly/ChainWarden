import unittest
from pathlib import Path

from chainwarden.certmodel import parse_certificate
from chainwarden.pemread import certificate_ders

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _load(name: str):
    ders = certificate_ders((SAMPLES / name).read_text())
    assert len(ders) == 1, name
    return parse_certificate(ders[0], source=name)


class TestCertModel(unittest.TestCase):
    def test_root_is_self_signed_ca(self):
        root = _load("root.pem")
        self.assertTrue(root.is_self_issued)
        self.assertTrue(root.basic_constraints.ca)
        self.assertEqual(root.common_name, "ChainWarden Test Root CA")
        self.assertEqual(root.rsa_modulus_bits, 2048)
