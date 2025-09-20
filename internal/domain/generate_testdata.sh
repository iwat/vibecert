#!/usr/bin/env bash
set -e
mkdir -p testdata

# RSA keys (2048, PKCS1)
openssl genrsa -traditional -out testdata/rsa_key_pkcs1.pem 2048
openssl rsa -traditional -in testdata/rsa_key_pkcs1.pem -aes256 -passout pass:secret -out testdata/rsa_key_pkcs1_enc.pem

# RSA keys (2048, PKCS8)
openssl genrsa -out testdata/rsa_key_pkcs8.pem 2048
openssl rsa -in testdata/rsa_key_pkcs8.pem -aes256 -passout pass:secret -out testdata/rsa_key_pkcs8_enc.pem

# ECDSA keys (P-256, SEC1)
openssl ecparam -name prime256v1 -genkey -noout -out testdata/ecdsa_key_sec1.pem
openssl ec -in testdata/ecdsa_key_sec1.pem -aes256 -passout pass:secret -out testdata/ecdsa_key_sec1_enc.pem

# ECDSA keys (P-256, PKCS8)
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out testdata/ecdsa_key_pkcs8.pem
openssl pkcs8 -topk8 -in testdata/ecdsa_key_pkcs8.pem -passout pass:secret -out testdata/ecdsa_key_pkcs8_enc.pem

# Ed25519 key (PKCS8)
openssl genpkey -algorithm Ed25519 -out testdata/ed25519_key_pkcs8.pem
openssl pkcs8 -topk8 -in testdata/ed25519_key_pkcs8.pem -passout pass:secret -out testdata/ed25519_key_pkcs8_enc.pem

# ECDH key (P-256, PKCS8)
# Note, X25519 is not supported in SEC1
openssl genpkey -algorithm X25519 -out testdata/ecdh_key_pkcs8.pem
openssl pkcs8 -topk8 -in testdata/ecdh_key_pkcs8.pem -passout pass:secret -out testdata/ecdh_key_pkcs8_enc.pem

# Self-signed certificate with PEM encoding
openssl req -x509 -newkey rsa:2048 -keyout testdata/rsa_cert_key.pem -out testdata/rsa_cert.crt \
  -days 365 -nodes -subj "/CN=Test Certificate Authority/C=CA/O=Example Org"
