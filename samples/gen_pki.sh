#!/bin/sh
# gen_pki.sh: regenerate the ChainWarden Test PKI with fixed validity dates.
# Requires openssl on PATH. All notBefore/notAfter values are pinned so the
# generated certificates are byte reproducible across runs and machines.
#
# Fixed dates (UTC):
#   root         2024-01-01 .. 2034-01-01
#   intermediate 2024-01-01 .. 2032-01-01
#   leaf-good    2025-01-01 .. 2027-01-01
#   leaf-soon    2025-01-01 .. 2026-10-01   (expiry cliff window with leaf-good)
#   leaf-expired 2023-01-01 .. 2024-06-01   (already expired)
#   leaf-weak    2025-01-01 .. 2028-01-01   (RSA 1024, SHA1 signature)
set -eu
cd "$(dirname "$0")"

ROOT_NB=20240101000000Z; ROOT_NA=20340101000000Z
INT_NB=20240101000000Z;  INT_NA=20320101000000Z
