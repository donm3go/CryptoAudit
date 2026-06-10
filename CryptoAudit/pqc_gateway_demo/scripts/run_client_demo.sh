#!/bin/sh
# Connects to the local PQC gateway as a client, forcing the same hybrid
# ML-KEM/Kyber group the server advertised, and records the full handshake
# transcript for later parsing into a quantum-readiness report.
set -eu

LOG_DIR=/demo/logs
GROUP=$(awk '{print $NF}' "$LOG_DIR/selected_group.txt")

echo "== Connecting with hybrid group: $GROUP =="

# 'Q' sends a quit after the handshake completes so s_client exits cleanly.
echo -e "GET / HTTP/1.0\r\nQ" | openssl s_client \
  -connect localhost:8443 \
  -groups "$GROUP" \
  -tls1_3 \
  -provider oqsprovider -provider default \
  -msg -debug \
  2>&1 | tee "$LOG_DIR/client_handshake.log"

echo "== Handshake transcript saved to $LOG_DIR/client_handshake.log =="
