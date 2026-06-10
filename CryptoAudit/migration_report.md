# Quantum-Readiness Migration Report

## Summary

- Total assets scanned: **21**
- Critical: **4**
- High: **12**
- Medium (quantum-weakened): **0**
- Safe / Quantum-resistant: **5**

## Findings

| Severity | Status | Asset Type | Resource | Detail | Recommendation |
|---|---|---|---|---|---|
| CRITICAL | Quantum-Vulnerable | Certificate | legacy-vpn.shopcart.example.com | RSA-1024 | Replace RSA-1024 with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) (or a hybrid RSA+PQC certificate during transition). |
| CRITICAL | Quantum-Vulnerable | TLS Config | legacy-api-elb (TLS 1.0) | TLS_RSA_WITH_3DES_EDE_CBC_SHA | Migrate to: AES-256-GCM or ChaCha20-Poly1305; ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites. |
| CRITICAL | Quantum-Vulnerable | TLS Config | legacy-api-elb (TLS 1.0) | TLS_RSA_WITH_RC4_128_SHA | Migrate to: AES-256-GCM or ChaCha20-Poly1305; ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites. |
| CRITICAL | Quantum-Vulnerable | TLS Config | prod-frontend-alb (TLS 1.2) | TLS_RSA_WITH_AES_128_CBC_SHA | Migrate to: AES-256; ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites. |
| HIGH | Quantum-Vulnerable | Certificate | internal-svc.contoso.local | RSA-4096 | Replace RSA-4096 with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) (or a hybrid RSA+PQC certificate during transition). |
| HIGH | Quantum-Vulnerable | Certificate | edge.shopcart.example.com | ECDSA-256 | Replace ECDSA with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) for signing, and ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange for key exchange. |
| HIGH | Quantum-Vulnerable | Certificate | api.shopcart.example.com | RSA-2048 | Replace RSA-2048 with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) (or a hybrid RSA+PQC certificate during transition). |
| HIGH | Quantum-Vulnerable | SSH Key | admin-jump-key | ECDSA-384 | Replace ECDSA with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) for signing, and ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange for key exchange. |
| HIGH | Quantum-Vulnerable | SSH Key | legacy-db-key | DSA-1024 | Replace DSA with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) for signing, and ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange for key exchange. |
| HIGH | Quantum-Vulnerable | SSH Key | prod-bastion-key | RSA-2048 | Replace RSA-2048 with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) (or a hybrid RSA+PQC certificate during transition). |
| HIGH | Quantum-Vulnerable | SSH Key | build-agent-key | ED25519-256 | Replace ED25519 with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) for signing, and ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange for key exchange. |
| HIGH | Quantum-Vulnerable | TLS Config | legacy-api-elb (TLS 1.0) | TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA | Migrate to: AES-256; ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites. |
| HIGH | Quantum-Vulnerable | TLS Config | analytics-internal-lb (TLS 1.2) | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 | Migrate to: ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites. |
| HIGH | Quantum-Vulnerable | TLS Config | analytics-internal-lb (TLS 1.2) | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 | Migrate to: AES-256; ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites. |
| HIGH | Quantum-Vulnerable | TLS Config | prod-frontend-alb (TLS 1.2) | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 | Migrate to: AES-256; ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites. |
| HIGH | Quantum-Vulnerable | TLS Config | prod-frontend-alb (TLS 1.2) | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 | Migrate to: ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites. |
| SAFE | Quantum-Safe | Certificate | pilot.contoso.local | ML-DSA-65 | No action needed. |
| SAFE | Quantum-Safe | TLS Config | payments-api-gateway (TLS 1.3) | TLS_AES_256_GCM_SHA384 | No action needed. |
| SAFE | Quantum-Safe | TLS Config | payments-api-gateway (TLS 1.3) | TLS_CHACHA20_POLY1305_SHA256 | No action needed. |
| SAFE | Quantum-Safe | TLS Config | pqc-gateway-demo (simulated API Gateway) (TLSv1.3) | TLS_AES_256_GCM_SHA384 | No action needed. |
| SAFE | Quantum-Safe | TLS Config | pqc-gateway-demo (simulated API Gateway) (TLSv1.3) | key-exchange group: SecP256r1MLKEM768 | No action needed. |

## Migration Plan

Recommended phases, ordered by severity:

1. **Critical** — assets vulnerable to both classical and quantum attacks today (e.g. RSA-1024, DSA, RC4/3DES, plain RSA key exchange). Rotate immediately.
2. **High** — assets safe today but broken by a cryptographically relevant quantum computer (RSA-2048+, ECDSA, ECDHE, Ed25519/X25519). Plan migration to hybrid classical+PQC or pure PQC (ML-DSA (Dilithium) or SLH-DSA (SPHINCS+), ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange) within your organization's crypto-agility roadmap.
3. **Medium** — symmetric algorithms weakened (not broken) by Grover's algorithm (AES-128, 3DES). Upgrade to AES-256 opportunistically.
4. **Safe** — already post-quantum or unaffected; no action required.

## Detail by Asset

### Certificate: legacy-vpn.shopcart.example.com
- Resource ID: `arn:aws:acm:us-east-1:111122223333:certificate/bbb-222`
- Algorithm/Detail: `RSA-1024`
- Status: **Quantum-Vulnerable** (Severity: CRITICAL)
- Reason: RSA relies on integer factorization or discrete-log hardness, both broken by Shor's algorithm on a CRQC.
- Recommendation: Replace RSA-1024 with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) (or a hybrid RSA+PQC certificate during transition).
- issuer: InternalCA
- expires: 2026-07-10

### TLS Config: legacy-api-elb (TLS 1.0)
- Resource ID: `elbv2/app/legacy-api/def456`
- Algorithm/Detail: `TLS_RSA_WITH_3DES_EDE_CBC_SHA`
- Status: **Quantum-Vulnerable** (Severity: CRITICAL)
- Reason: RSA key exchange (quantum-broken); RSA authentication (quantum-broken); legacy/broken bulk cipher (quantum-broken)
- Recommendation: Migrate to: AES-256-GCM or ChaCha20-Poly1305; ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites.
- min_tls_version: TLS 1.0

### TLS Config: legacy-api-elb (TLS 1.0)
- Resource ID: `elbv2/app/legacy-api/def456`
- Algorithm/Detail: `TLS_RSA_WITH_RC4_128_SHA`
- Status: **Quantum-Vulnerable** (Severity: CRITICAL)
- Reason: RSA key exchange (quantum-broken); RSA authentication (quantum-broken); legacy/broken bulk cipher (quantum-broken)
- Recommendation: Migrate to: AES-256-GCM or ChaCha20-Poly1305; ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites.
- min_tls_version: TLS 1.0

### TLS Config: prod-frontend-alb (TLS 1.2)
- Resource ID: `elbv2/app/prod-frontend/abc123`
- Algorithm/Detail: `TLS_RSA_WITH_AES_128_CBC_SHA`
- Status: **Quantum-Vulnerable** (Severity: CRITICAL)
- Reason: RSA key exchange (quantum-broken); RSA authentication (quantum-broken); AES-128 bulk cipher (quantum-weakened)
- Recommendation: Migrate to: AES-256; ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites.
- min_tls_version: TLS 1.2

### Certificate: internal-svc.contoso.local
- Resource ID: `kv:contoso-vault:cert/internal-svc`
- Algorithm/Detail: `RSA-4096`
- Status: **Quantum-Vulnerable** (Severity: HIGH)
- Reason: RSA relies on integer factorization or discrete-log hardness, both broken by Shor's algorithm on a CRQC.
- Recommendation: Replace RSA-4096 with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) (or a hybrid RSA+PQC certificate during transition).
- issuer: ContosoCA
- expires: 2027-07-15

### Certificate: edge.shopcart.example.com
- Resource ID: `arn:aws:acm:eu-west-1:111122223333:certificate/ccc-333`
- Algorithm/Detail: `ECDSA-256`
- Status: **Quantum-Vulnerable** (Severity: HIGH)
- Reason: ECDSA relies on integer factorization or discrete-log hardness, both broken by Shor's algorithm on a CRQC.
- Recommendation: Replace ECDSA with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) for signing, and ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange for key exchange.
- issuer: Amazon
- expires: 2027-04-06

### Certificate: api.shopcart.example.com
- Resource ID: `arn:aws:acm:us-east-1:111122223333:certificate/aaa-111`
- Algorithm/Detail: `RSA-2048`
- Status: **Quantum-Vulnerable** (Severity: HIGH)
- Reason: RSA relies on integer factorization or discrete-log hardness, both broken by Shor's algorithm on a CRQC.
- Recommendation: Replace RSA-2048 with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) (or a hybrid RSA+PQC certificate during transition).
- issuer: Amazon
- expires: 2026-12-07

### SSH Key: admin-jump-key
- Resource ID: `ec2-keypair/admin-jump`
- Algorithm/Detail: `ECDSA-384`
- Status: **Quantum-Vulnerable** (Severity: HIGH)
- Reason: ECDSA relies on integer factorization or discrete-log hardness, both broken by Shor's algorithm on a CRQC.
- Recommendation: Replace ECDSA with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) for signing, and ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange for key exchange.
- attached_to: ['i-0a1b2c3d4e5f60004 (jump-host)']

### SSH Key: legacy-db-key
- Resource ID: `ec2-keypair/legacy-db`
- Algorithm/Detail: `DSA-1024`
- Status: **Quantum-Vulnerable** (Severity: HIGH)
- Reason: DSA relies on integer factorization or discrete-log hardness, both broken by Shor's algorithm on a CRQC.
- Recommendation: Replace DSA with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) for signing, and ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange for key exchange.
- attached_to: ['i-0a1b2c3d4e5f60003 (db-archive)']

### SSH Key: prod-bastion-key
- Resource ID: `ec2-keypair/prod-bastion`
- Algorithm/Detail: `RSA-2048`
- Status: **Quantum-Vulnerable** (Severity: HIGH)
- Reason: RSA relies on integer factorization or discrete-log hardness, both broken by Shor's algorithm on a CRQC.
- Recommendation: Replace RSA-2048 with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) (or a hybrid RSA+PQC certificate during transition).
- attached_to: ['i-0a1b2c3d4e5f60001 (bastion-host)']

### SSH Key: build-agent-key
- Resource ID: `ec2-keypair/build-agent`
- Algorithm/Detail: `ED25519-256`
- Status: **Quantum-Vulnerable** (Severity: HIGH)
- Reason: ED25519 relies on integer factorization or discrete-log hardness, both broken by Shor's algorithm on a CRQC.
- Recommendation: Replace ED25519 with ML-DSA (Dilithium) or SLH-DSA (SPHINCS+) for signing, and ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange for key exchange.
- attached_to: ['i-0a1b2c3d4e5f60002 (ci-runner-1)']

### TLS Config: legacy-api-elb (TLS 1.0)
- Resource ID: `elbv2/app/legacy-api/def456`
- Algorithm/Detail: `TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA`
- Status: **Quantum-Vulnerable** (Severity: HIGH)
- Reason: ECDHE key exchange (quantum-broken); RSA authentication (quantum-broken); AES-128 bulk cipher (quantum-weakened)
- Recommendation: Migrate to: AES-256; ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites.
- min_tls_version: TLS 1.0

### TLS Config: analytics-internal-lb (TLS 1.2)
- Resource ID: `lb/internal/analytics`
- Algorithm/Detail: `TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384`
- Status: **Quantum-Vulnerable** (Severity: HIGH)
- Reason: ECDHE key exchange (quantum-broken); ECDSA authentication (quantum-broken)
- Recommendation: Migrate to: ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites.
- min_tls_version: TLS 1.2

### TLS Config: analytics-internal-lb (TLS 1.2)
- Resource ID: `lb/internal/analytics`
- Algorithm/Detail: `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`
- Status: **Quantum-Vulnerable** (Severity: HIGH)
- Reason: ECDHE key exchange (quantum-broken); ECDSA authentication (quantum-broken); AES-128 bulk cipher (quantum-weakened)
- Recommendation: Migrate to: AES-256; ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites.
- min_tls_version: TLS 1.2

### TLS Config: prod-frontend-alb (TLS 1.2)
- Resource ID: `elbv2/app/prod-frontend/abc123`
- Algorithm/Detail: `TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256`
- Status: **Quantum-Vulnerable** (Severity: HIGH)
- Reason: ECDHE key exchange (quantum-broken); RSA authentication (quantum-broken); AES-128 bulk cipher (quantum-weakened)
- Recommendation: Migrate to: AES-256; ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites.
- min_tls_version: TLS 1.2

### TLS Config: prod-frontend-alb (TLS 1.2)
- Resource ID: `elbv2/app/prod-frontend/abc123`
- Algorithm/Detail: `TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384`
- Status: **Quantum-Vulnerable** (Severity: HIGH)
- Reason: ECDHE key exchange (quantum-broken); RSA authentication (quantum-broken)
- Recommendation: Migrate to: ML-DSA (Dilithium) or SLH-DSA (SPHINCS+); ML-KEM (Kyber) or a hybrid X25519+ML-KEM key exchange. Prefer TLS 1.3 cipher suites.
- min_tls_version: TLS 1.2

### Certificate: pilot.contoso.local
- Resource ID: `kv:contoso-vault:cert/pqc-pilot`
- Algorithm/Detail: `ML-DSA-65`
- Status: **Quantum-Safe** (Severity: SAFE)
- Reason: ML-DSA-65 is a NIST post-quantum algorithm.
- Recommendation: No action needed.
- issuer: ContosoCA-PQC
- expires: 2027-06-10

### TLS Config: payments-api-gateway (TLS 1.3)
- Resource ID: `apigw/payments-api`
- Algorithm/Detail: `TLS_AES_256_GCM_SHA384`
- Status: **Quantum-Safe** (Severity: SAFE)
- Reason: TLS_AES_256_GCM_SHA384 uses no algorithms with known quantum breaks.
- Recommendation: No action needed.
- min_tls_version: TLS 1.3

### TLS Config: payments-api-gateway (TLS 1.3)
- Resource ID: `apigw/payments-api`
- Algorithm/Detail: `TLS_CHACHA20_POLY1305_SHA256`
- Status: **Quantum-Safe** (Severity: SAFE)
- Reason: TLS_CHACHA20_POLY1305_SHA256 uses no algorithms with known quantum breaks.
- Recommendation: No action needed.
- min_tls_version: TLS 1.3

### TLS Config: pqc-gateway-demo (simulated API Gateway) (TLSv1.3)
- Resource ID: `pqc-gateway-demo/local`
- Algorithm/Detail: `TLS_AES_256_GCM_SHA384`
- Status: **Quantum-Safe** (Severity: SAFE)
- Reason: TLS_AES_256_GCM_SHA384 uses no algorithms with known quantum breaks.
- Recommendation: No action needed.
- min_tls_version: TLSv1.3

### TLS Config: pqc-gateway-demo (simulated API Gateway) (TLSv1.3)
- Resource ID: `pqc-gateway-demo/local`
- Algorithm/Detail: `key-exchange group: SecP256r1MLKEM768`
- Status: **Quantum-Safe** (Severity: SAFE)
- Reason: SecP256r1MLKEM768 is a hybrid key exchange combining a classical ECDH share with an ML-KEM/Kyber share — recovering the shared secret requires breaking both.
- Recommendation: No action needed.
- min_tls_version: TLSv1.3
