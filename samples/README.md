# Sample certificate fixtures

These PEM files are a real test PKI generated with OpenSSL 3.6.1 on the machine
that built this project. They are test vectors, not production certificates.
Every private key was discarded after signing, so nothing here can be used to
impersonate anything. The subject names use the reserved `.test` label and the
organisation is literally "ChainWarden Test PKI".

## What is here

| File               | Role         | Key        | Signature              | notAfter    |
|--------------------|--------------|------------|------------------------|-------------|
| `root.pem`         | root CA      | RSA 2048   | sha256WithRSAEncryption| 2034-01-01  |
| `intermediate.pem` | intermediate | RSA 2048   | sha256WithRSAEncryption| 2032-01-01  |
| `leaf-good.pem`    | leaf         | RSA 2048   | sha256WithRSAEncryption| 2027-01-01  |
| `leaf-soon.pem`    | leaf         | RSA 2048   | sha256WithRSAEncryption| 2026-10-01  |
| `leaf-expired.pem` | leaf         | RSA 2048   | sha256WithRSAEncryption| 2024-06-01  |
| `leaf-weak.pem`    | leaf         | RSA 1024   | sha1WithRSAEncryption  | 2028-01-01  |
| `bundle.pem`       | all six certs concatenated, in the order above                |

`leaf-expired.pem` is already past its notAfter. `leaf-weak.pem` uses both a
