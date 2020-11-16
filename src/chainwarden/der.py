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
