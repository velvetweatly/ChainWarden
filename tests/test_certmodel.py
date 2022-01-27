import unittest
from pathlib import Path

from chainwarden.certmodel import parse_certificate
from chainwarden.pemread import certificate_ders

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def _load(name: str):
    ders = certificate_ders((SAMPLES / name).read_text())
