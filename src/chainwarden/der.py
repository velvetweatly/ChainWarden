"""Minimal DER/ASN.1 reader.

This is a tag-length-value walker, not a full ASN.1 decoder. It reaches only
the fields chainwarden needs from an X.509 certificate: version, serial,
signature algorithm OID, issuer and subject RDN sequences, the validity dates,
the subject public key algorithm and modulus size, and the extension list.

References: RFC 5280 section 4.1 (Certificate), ITU-T X.690 (DER encoding).
The parser is deliberately strict about lengths and rejects indefinite-length
encodings, which DER forbids anyway.
"""

from __future__ import annotations

from dataclasses import dataclass


class DERError(ValueError):
    """Raised when a byte string is not well formed DER for our purposes."""


# ASN.1 universal tag numbers we care about.
TAG_BOOLEAN = 0x01
TAG_INTEGER = 0x02
TAG_BIT_STRING = 0x03
TAG_OCTET_STRING = 0x04
TAG_NULL = 0x05
TAG_OID = 0x06
TAG_UTF8_STRING = 0x0C
TAG_SEQUENCE = 0x30
TAG_SET = 0x31
TAG_PRINTABLE_STRING = 0x13
