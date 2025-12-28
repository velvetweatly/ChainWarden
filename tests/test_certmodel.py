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
        self.assertEqual(root.sig_alg_name, "sha256WithRSAEncryption")

    def test_intermediate_pathlen(self):
        inter = _load("intermediate.pem")
        self.assertFalse(inter.is_self_issued)
        self.assertTrue(inter.basic_constraints.ca)
        self.assertEqual(inter.basic_constraints.path_len, 0)

    def test_leaf_good_fields(self):
        leaf = _load("leaf-good.pem")
        self.assertEqual(leaf.common_name, "good.example.test")
        self.assertFalse(leaf.basic_constraints.ca)
        self.assertIn("digitalSignature", leaf.key_usage)
        self.assertIn("serverAuth", leaf.ext_key_usage)
        self.assertEqual(leaf.not_after.date().isoformat(), "2027-01-01")

    def test_leaf_weak_key_and_sig(self):
        weak = _load("leaf-weak.pem")
        self.assertEqual(weak.rsa_modulus_bits, 1024)
        self.assertEqual(weak.sig_alg_name, "sha1WithRSAEncryption")

    def test_leaf_expired_dates(self):
        exp = _load("leaf-expired.pem")
        self.assertEqual(exp.not_after.date().isoformat(), "2024-06-01")

    def test_serials(self):
        self.assertEqual(_load("root.pem").serial, 1)
        self.assertEqual(_load("intermediate.pem").serial, 2)
        self.assertEqual(_load("leaf-good.pem").serial, 16)

    def test_fingerprint_is_stable_hex(self):
        fp = _load("root.pem").fingerprint_sha256
        self.assertEqual(len(fp), 64)
        int(fp, 16)  # parses as hex


if __name__ == "__main__":
    unittest.main()

