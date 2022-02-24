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
                "soon.example.test",
                "weak.example.test",
            ],
        )

    def test_good_chain_reaches_root(self):
        leaf = next(c for c in self.certs if c.common_name == "good.example.test")
        chain = build_chain(leaf, self.certs)
        self.assertEqual(chain.depth, 3)
        self.assertTrue(chain.complete)
        self.assertEqual(chain.anchor.common_name, "ChainWarden Test Root CA")

    def test_incomplete_chain_when_root_absent(self):
        no_root = [c for c in self.certs if not c.is_self_issued]
        leaf = next(c for c in no_root if c.common_name == "good.example.test")
        chain = build_chain(leaf, no_root)
        self.assertFalse(chain.complete)

    def test_all_chains_count(self):
        self.assertEqual(len(build_all_chains(self.certs)), 4)


class TestPolicy(unittest.TestCase):
    def setUp(self):
        self.certs = _load_all(ALL_NAMES)
        self.chains = build_all_chains(self.certs)

    def test_audit_flags_expired_weak_key_and_sig(self):
        cfg = AuditConfig(as_of=date(2026, 9, 2))
        findings = run_audit(self.certs, self.chains, cfg)
        codes = {f.code for f in findings}
        self.assertIn("EXPIRED", codes)
        self.assertIn("WEAK_KEY", codes)
        self.assertIn("WEAK_SIG", codes)

    def test_findings_sorted_errors_first(self):
        cfg = AuditConfig(as_of=date(2026, 9, 2))
        findings = run_audit(self.certs, self.chains, cfg)
        severities = [f.severity for f in findings]
