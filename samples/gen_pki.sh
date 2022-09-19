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
GOOD_NB=20250101000000Z; GOOD_NA=20270101000000Z
SOON_NB=20250101000000Z; SOON_NA=20261001000000Z
EXP_NB=20230101000000Z;  EXP_NA=20240601000000Z
WEAK_NB=20250101000000Z; WEAK_NA=20280101000000Z

# --- root CA (RSA 2048, SHA256, self signed) ---
openssl req -new -newkey rsa:2048 -nodes \
  -keyout root.key -out root.csr \
  -subj "/C=US/O=ChainWarden Test PKI/CN=ChainWarden Test Root CA"

cat > ext_root.cnf <<'EOF'
basicConstraints=critical,CA:TRUE
keyUsage=critical,keyCertSign,cRLSign
EOF

openssl x509 -req -in root.csr -signkey root.key \
  -set_serial 1 -sha256 \
  -not_before "$ROOT_NB" -not_after "$ROOT_NA" \
  -extfile ext_root.cnf -out root.pem

# --- intermediate CA key and CSR ---
openssl req -new -newkey rsa:2048 -nodes \
  -keyout intermediate.key -out intermediate.csr \
  -subj "/C=US/O=ChainWarden Test PKI/CN=ChainWarden Test Intermediate CA"

cat > ext_int.cnf <<'EOF'
basicConstraints=critical,CA:TRUE,pathlen:0
keyUsage=critical,keyCertSign,cRLSign
EOF

openssl x509 -req -in intermediate.csr \
  -CA root.pem -CAkey root.key -set_serial 2 \
  -sha256 -not_before "$INT_NB" -not_after "$INT_NA" \
  -extfile ext_int.cnf -out intermediate.pem

# --- leaf-good (RSA 2048, SHA256) ---
openssl req -new -newkey rsa:2048 -nodes \
  -keyout leaf-good.key -out leaf-good.csr \
  -subj "/C=US/O=ChainWarden Test PKI/CN=good.example.test"
cat > ext_leaf.cnf <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
EOF
openssl x509 -req -in leaf-good.csr \
  -CA intermediate.pem -CAkey intermediate.key -set_serial 16 \
  -sha256 -not_before "$GOOD_NB" -not_after "$GOOD_NA" \
  -extfile ext_leaf.cnf -out leaf-good.pem

# --- leaf-soon (RSA 2048, SHA256, expires close to leaf-good) ---
openssl req -new -newkey rsa:2048 -nodes \
  -keyout leaf-soon.key -out leaf-soon.csr \
  -subj "/C=US/O=ChainWarden Test PKI/CN=soon.example.test"
openssl x509 -req -in leaf-soon.csr \
  -CA intermediate.pem -CAkey intermediate.key -set_serial 17 \
  -sha256 -not_before "$SOON_NB" -not_after "$SOON_NA" \
  -extfile ext_leaf.cnf -out leaf-soon.pem

# --- leaf-expired (RSA 2048, SHA256, already expired) ---
openssl req -new -newkey rsa:2048 -nodes \
