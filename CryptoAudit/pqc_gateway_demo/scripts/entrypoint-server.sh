#!/bin/sh
# Starts a TLS 1.3 server offering a hybrid post-quantum key exchange group
# (classical ECDHE curve combined with ML-KEM/Kyber), simulating the
# TLS-terminating side of a cloud "API Gateway" resource.
set -eu

CERT_DIR=/demo/certs
LOG_DIR=/demo/logs
mkdir -p "$CERT_DIR" "$LOG_DIR"

echo "== OpenSSL version ==" | tee "$LOG_DIR/openssl_version.txt"
openssl version -a | tee -a "$LOG_DIR/openssl_version.txt"

echo "== Available providers ==" | tee "$LOG_DIR/providers.txt"
(openssl list -providers -provider oqsprovider -provider default 2>/dev/null \
  || openssl list -providers) | tee -a "$LOG_DIR/providers.txt"

# Discover a hybrid ML-KEM/Kyber group (classical curve + PQC KEM combo).
# Naming has changed across oqs-provider/OpenSSL versions, so search rather
# than hardcode:
#   newer (IETF draft / OpenSSL 3.5+):  X25519MLKEM768, SecP256r1MLKEM768
#   older (oqs-provider pre-FIPS203):   x25519_kyber768, p256_kyber768
find_group() {
  local listing
  listing=$( (openssl list -kem-algorithms -provider oqsprovider -provider default 2>/dev/null \
              || openssl list -kem-algorithms 2>/dev/null) || true)
  echo "$listing" | grep -ioE '[a-z0-9]*(x25519|p256|secp256r1)[a-z0-9_]*(mlkem|kyber)[a-z0-9_]*' | head -1 \
    || echo "$listing" | grep -ioE '[a-z0-9]*(mlkem|kyber)[a-z0-9_]*(x25519|p256|secp256r1)[a-z0-9_]*' | head -1 \
    || true
}

GROUP=$(find_group)
if [ -z "$GROUP" ]; then
  # Fallback to the IETF draft / OpenSSL 3.5+ native name.
  GROUP="X25519MLKEM768"
fi
echo "Selected hybrid KEM group: $GROUP" | tee "$LOG_DIR/selected_group.txt"

# Generate a self-signed server certificate (classical ECDSA P-256 signature).
# The cert's signature algorithm is intentionally classical here to show that
# key-exchange and certificate-signature migrations are independent phases
# (see TUTORIAL.md / RUNBOOK.md).
if [ ! -f "$CERT_DIR/server.key" ]; then
  openssl req -x509 -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 \
    -keyout "$CERT_DIR/server.key" -out "$CERT_DIR/server.crt" \
    -nodes -days 365 -subj "/CN=pqc-gateway.mockcloud.local" \
    2>&1 | tee "$LOG_DIR/cert_generation.log"
fi

echo "== Starting hybrid PQC TLS server on :8443 (group=$GROUP) ==" | tee -a "$LOG_DIR/server.log"
exec openssl s_server -accept 8443 \
  -cert "$CERT_DIR/server.crt" -key "$CERT_DIR/server.key" \
  -tls1_3 -groups "$GROUP" -www \
  -provider oqsprovider -provider default \
  2>&1 | tee -a "$LOG_DIR/server.log"
