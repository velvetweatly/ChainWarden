import unittest
from datetime import date
from pathlib import Path

from chainwarden.certmodel import parse_certificate
from chainwarden.chainbuild import build_all_chains, build_chain, find_leaves
from chainwarden.pemread import certificate_ders
from chainwarden.policy import AuditConfig, check_expiry_cliff, run_audit

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _load_all(names):
    certs = []
    for name in names:
        for d in certificate_ders((SAMPLES / name).read_text()):
            certs.append(parse_certificate(d, source=name))
    return certs


ALL_NAMES = [
    "root.pem",
    "intermediate.pem",
    "leaf-good.pem",
    "leaf-soon.pem",
    "leaf-expired.pem",
    "leaf-weak.pem",
]


class TestChainBuild(unittest.TestCase):
    def setUp(self):
        self.certs = _load_all(ALL_NAMES)

    def test_four_leaves_detected(self):
        leaves = find_leaves(self.certs)
        names = sorted(c.common_name for c in leaves)
        self.assertEqual(
            names,
            [
                "expired.example.test",
                "good.example.test",
