"""The Certificate model and the code that fills it from DER.

Structure walked (RFC 5280 section 4.1):

    Certificate ::= SEQUENCE {
        tbsCertificate       TBSCertificate,
        signatureAlgorithm   AlgorithmIdentifier,
        signatureValue       BIT STRING }

    TBSCertificate ::= SEQUENCE {
        version         [0] EXPLICIT INTEGER DEFAULT v1,
        serialNumber        INTEGER,
        signature           AlgorithmIdentifier,
        issuer              Name,
        validity            Validity,
        subject             Name,
        subjectPublicKeyInfo SubjectPublicKeyInfo,
        ... extensions [3] EXPLICIT Extensions OPTIONAL }

We do not verify signatures. This tool inspects structure and policy, it is not
a validating path builder in the cryptographic sense, and it says so.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone

from . import der
from .der import TLV

# OID tables. Kept small and explicit so the report can name algorithms.
SIG_ALG_NAMES = {
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.113549.1.1.11": "sha256WithRSAEncryption",
    "1.2.840.113549.1.1.12": "sha384WithRSAEncryption",
    "1.2.840.113549.1.1.13": "sha512WithRSAEncryption",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
    "1.2.840.10045.4.3.2": "ecdsa-with-SHA256",
    "1.2.840.10045.4.3.3": "ecdsa-with-SHA384",
}

PUBKEY_ALG_NAMES = {
    "1.2.840.113549.1.1.1": "rsaEncryption",
    "1.2.840.10045.2.1": "id-ecPublicKey",
    "1.3.101.112": "Ed25519",
}

# Attribute type OIDs for RDN components we render.
ATTR_NAMES = {
    "2.5.4.3": "CN",
    "2.5.4.6": "C",
    "2.5.4.7": "L",
    "2.5.4.8": "ST",
    "2.5.4.10": "O",
    "2.5.4.11": "OU",
}

# Extension OIDs.
EXT_BASIC_CONSTRAINTS = "2.5.29.19"
EXT_KEY_USAGE = "2.5.29.15"
EXT_EXT_KEY_USAGE = "2.5.29.37"
EXT_SUBJECT_ALT_NAME = "2.5.29.17"

# Key usage bit names in order (RFC 5280 section 4.2.1.3).
KEY_USAGE_BITS = [
    "digitalSignature",
    "nonRepudiation",
    "keyEncipherment",
    "dataEncipherment",
    "keyAgreement",
    "keyCertSign",
    "cRLSign",
    "encipherOnly",
    "decipherOnly",
]


class CertParseError(ValueError):
    """Raised when a DER buffer does not parse as an X.509 certificate."""


@dataclass(frozen=True)
class BasicConstraints:
    present: bool = False
    critical: bool = False
    ca: bool = False
    path_len: int | None = None


@dataclass
class Certificate:
    """A parsed certificate. Times are timezone aware UTC datetimes."""

    subject: str
    issuer: str
    serial: int
    not_before: datetime
    not_after: datetime
    sig_alg_oid: str
    pubkey_alg_oid: str
    rsa_modulus_bits: int | None
    basic_constraints: BasicConstraints
    key_usage: list[str] = field(default_factory=list)
    ext_key_usage: list[str] = field(default_factory=list)
    subject_alt_names: list[str] = field(default_factory=list)
    fingerprint_sha256: str = ""
    source: str = ""

    @property
    def sig_alg_name(self) -> str:
        return SIG_ALG_NAMES.get(self.sig_alg_oid, self.sig_alg_oid)

    @property
    def pubkey_alg_name(self) -> str:
        return PUBKEY_ALG_NAMES.get(self.pubkey_alg_oid, self.pubkey_alg_oid)

    @property
    def is_self_issued(self) -> bool:
        return self.subject == self.issuer

    @property
    def common_name(self) -> str:
        for part in self.subject.split(","):
            part = part.strip()
            if part.startswith("CN="):
                return part[3:]
        return self.subject


def _parse_time(tlv: TLV) -> datetime:
    text = tlv.value.decode("ascii")
    if tlv.tag == der.TAG_UTC_TIME:
        # YYMMDDHHMMSSZ. RFC 5280: years 50..99 => 19xx, 00..49 => 20xx.
        if not text.endswith("Z"):
            raise CertParseError("unexpected UTCTime form")
        yy = int(text[0:2])
        year = 1900 + yy if yy >= 50 else 2000 + yy
        return datetime(
            year,
            int(text[2:4]),
            int(text[4:6]),
            int(text[6:8]),
            int(text[8:10]),
            int(text[10:12]),
            tzinfo=timezone.utc,
        )
    if tlv.tag == der.TAG_GENERALIZED_TIME:
        # YYYYMMDDHHMMSSZ.
        if not text.endswith("Z"):
            raise CertParseError("unexpected GeneralizedTime form")
        return datetime(
            int(text[0:4]),
            int(text[4:6]),
            int(text[6:8]),
            int(text[8:10]),
            int(text[10:12]),
            int(text[12:14]),
            tzinfo=timezone.utc,
        )
    raise CertParseError(f"unexpected time tag {tlv.tag:#x}")


def _parse_name(name_tlv: TLV, buf: bytes) -> str:
    """Render a Name as a comma joined RDN string, for example
    'C=US, O=Example, CN=host'. Multi valued RDNs are joined with '+'."""
    rdns: list[str] = []
    for rdn in der.read_children(name_tlv, buf):
        atvs: list[str] = []
        for atv in der.read_children(rdn, buf):
            fields = der.read_children(atv, buf)
            if len(fields) != 2:
                continue
            oid = der.decode_oid(fields[0].value)
            key = ATTR_NAMES.get(oid, oid)
            val = fields[1].value.decode("utf-8", errors="replace")
            atvs.append(f"{key}={val}")
        rdns.append("+".join(atvs))
    return ", ".join(rdns)


def _alg_oid(alg_tlv: TLV, buf: bytes) -> str:
    children = der.read_children(alg_tlv, buf)
    if not children or children[0].tag != der.TAG_OID:
        raise CertParseError("AlgorithmIdentifier missing OID")
    return der.decode_oid(children[0].value)


def _parse_spki(spki: TLV, buf: bytes) -> tuple[str, int | None]:
    """Return (pubkey_alg_oid, rsa_modulus_bits or None)."""
    children = der.read_children(spki, buf)
    if len(children) < 2:
        raise CertParseError("SubjectPublicKeyInfo malformed")
    alg_oid = _alg_oid(children[0], buf)
    modulus_bits: int | None = None
    if alg_oid == "1.2.840.113549.1.1.1":  # rsaEncryption
        bit_string = children[1]
        if bit_string.tag != der.TAG_BIT_STRING or not bit_string.value:
            raise CertParseError("RSA public key BIT STRING malformed")
        # First byte of a BIT STRING is the count of unused bits.
        rsa_key_der = bit_string.value[1:]
        seq = der.read_tlv(rsa_key_der, 0)
        parts = der.read_children(seq, rsa_key_der)
        if not parts or parts[0].tag != der.TAG_INTEGER:
            raise CertParseError("RSA modulus missing")
        modulus_bits = der.integer_bit_length(parts[0].value)
    return alg_oid, modulus_bits


def _parse_extensions(ext_tlv: TLV, buf: bytes, cert_fields: dict) -> None:
    # ext_tlv is the [3] EXPLICIT wrapper; its single child is the SEQUENCE.
    inner = der.read_children(ext_tlv, buf)
    if not inner:
        return
    for ext in der.read_children(inner[0], buf):
        parts = der.read_children(ext, buf)
        if not parts:
            continue
        oid = der.decode_oid(parts[0].value)
        idx = 1
        critical = False
        if idx < len(parts) and parts[idx].tag == der.TAG_BOOLEAN:
            critical = parts[idx].value != b"\x00"
            idx += 1
        if idx >= len(parts):
            continue
        ext_value = parts[idx].value  # OCTET STRING content
        if oid == EXT_BASIC_CONSTRAINTS:
            cert_fields["basic_constraints"] = _parse_basic_constraints(
                ext_value, critical
            )
        elif oid == EXT_KEY_USAGE:
            cert_fields["key_usage"] = _parse_key_usage(ext_value)
        elif oid == EXT_EXT_KEY_USAGE:
