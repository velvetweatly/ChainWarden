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
TAG_IA5_STRING = 0x16
TAG_UTC_TIME = 0x17
TAG_GENERALIZED_TIME = 0x18


@dataclass(frozen=True)
class TLV:
    """One tag-length-value triple parsed from a DER buffer."""

    tag: int
    # Byte offset of the value (content), relative to the buffer start.
    value_start: int
    # Length of the value in bytes.
    length: int
    # The raw content bytes.
    value: bytes
    # Byte offset just past this TLV, useful when walking siblings.
    end: int


def read_tlv(buf: bytes, offset: int = 0) -> TLV:
    """Read one TLV starting at offset. Rejects indefinite lengths."""
    if offset >= len(buf):
        raise DERError("read past end of buffer")
    tag = buf[offset]
    pos = offset + 1
    if pos >= len(buf):
        raise DERError("truncated length")
    first = buf[pos]
    pos += 1
    if first < 0x80:
        length = first
    elif first == 0x80:
        raise DERError("indefinite length is not valid DER")
