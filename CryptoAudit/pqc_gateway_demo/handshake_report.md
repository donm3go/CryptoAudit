# PQC Gateway Handshake Report

## Result

- Handshake completed: **YES**
- Negotiated protocol: `TLSv1.3`
- Negotiated cipher: `TLS_AES_256_GCM_SHA384`
- Requested hybrid KEM group: `SecP256r1MLKEM768`
- Server Temp Key (negotiated key-exchange group): `SecP256r1MLKEM768`
- Certificate verify return code: `18 (self-signed certificate)` (non-zero is expected — server cert is self-signed)
- Key-exchange status: **Quantum-Safe (key exchange)**

## Interpretation

The TLS 1.3 handshake completed successfully using a **hybrid post-quantum key exchange group (SecP256r1MLKEM768)**. This combines a classical ECDHE share with an ML-KEM/Kyber share — an eavesdropper recording this session today cannot recover the shared secret even with a future cryptographically relevant quantum computer, because breaking it requires breaking *both* the classical ECDH share *and* the ML-KEM share.

Note: the **server certificate's signature algorithm is still classical ECDSA P-256** (see `certs/server.crt`). Key exchange and certificate-signature migrations are independent — this gateway has completed phase 1 (key exchange) but still needs phase 2 (PQC/hybrid certificate signatures, e.g. ML-DSA) to fully close the 'harvest now, decrypt later' gap for authentication.
