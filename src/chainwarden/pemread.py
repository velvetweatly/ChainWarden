"""PEM reading: split a text buffer into labelled base64 blocks and decode.

A PEM block looks like:

    -----BEGIN CERTIFICATE-----
    <base64>
    -----END CERTIFICATE-----

We only decode CERTIFICATE blocks. Other labels (keys, CSRs) are skipped so a
bundle that mixes material does not crash the reader.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass

_BEGIN = "-----BEGIN "
_END = "-----END "
_SUFFIX = "-----"


class PEMError(ValueError):
    """Raised when a PEM block is malformed."""


@dataclass(frozen=True)
class PEMBlock:
    label: str
