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
