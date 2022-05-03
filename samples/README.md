# Sample certificate fixtures

These PEM files are a real test PKI generated with OpenSSL 3.6.1 on the machine
that built this project. They are test vectors, not production certificates.
Every private key was discarded after signing, so nothing here can be used to
impersonate anything. The subject names use the reserved `.test` label and the
organisation is literally "ChainWarden Test PKI".

## What is here

| File               | Role         | Key        | Signature              | notAfter    |
