# Crypto Auditor

A python prototype for auditing an organization's current cryptographic keys, enumerating their size, and evaluating whether or not they are "Quantum Safe" before further migration and mitigation processes can take place.

## 1. The core problem: "harvest now, decrypt later"

The threat model for post-quantum migration isn't "a quantum computer will
break my TLS session tomorrow." It's that an adversary can **record
encrypted traffic and certificates today**, then decrypt them once a
cryptographically relevant quantum computer (CRQC) exists. That means this
auditing tool isn't about what's exploitable *now* — it's about **inventory**:
knowing where every RSA/ECC key, certificate, and cipher suite lives so an
organization can plan rotation before that becomes urgent.

This shaped my first design decision: the script is a **scanner +
classifier + reporter**, not a vulnerability checker. It doesn't try to
prove an asset is currently exploitable — it tells you "this algorithm's
regardless of key size."

## 2. Why classify by *algorithm family*, not key size

A common instinct is "RSA-2048 is fine, RSA-1024 is bad." That's true for
**classical** attacks, but irrelevant for quantum ones — Shor's algorithm
breaks RSA and ECC of *any* key size with the same polynomial-time
complexity class. So:

- `SHOR_VULNERABLE_PATTERNS` matches RSA, DSA, ECDSA, ECDH, EC*, Ed25519/448,
  X25519/448 — **all of these are "Quantum-Vulnerable" regardless of size.**
- Key size only affects **severity**, because it still matters for
  *classical* security today (RSA-1024 is CRITICAL because it's already
  weak classically; RSA-4096 is HIGH because it's fine today but still
  doomed against Shor).
- `GROVER_WEAKENED_PATTERNS` (AES-128, 3DES) get a separate "Quantum-Weakened"
  status — Grover's algorithm only gives a quadratic speedup, so doubling
  key length (AES-128 → AES-256) restores the original security margin.
  This is a *fix by parameter change*, not an algorithm swap.
- `PQC_PATTERNS` (ML-KEM/Kyber, ML-DSA/Dilithium, SLH-DSA/SPHINCS+, Falcon)
  are marked "Quantum-Safe" — these are the NIST-selected replacements.

Keeping these three buckets (Shor-broken / Grover-weakened / PQC-or-fine)
distinct is the single most important modeling decision, because it drives
*different remediation paths* (algorithm swap vs. key-size bump vs. no-op).

## 3. Why TLS cipher suites are scanned separately from certificates

A certificate tells you about the **signature algorithm** (how the cert is
authenticated). A cipher suite tells you about the **key exchange** and
**bulk cipher** actually negotiated on the wire. A server can have a
PQC-ready certificate but still offer `TLS_RSA_WITH_3DES_EDE_CBC_SHA` to
legacy clients. `classify_cipher_suite` decomposes the suite name into its
components (key exchange, authentication, bulk cipher) and reports *all*
issues found, not just the worst one — because each component needs its own
remediation (e.g., swap RSA key exchange for ML-KEM, *and* drop 3DES for
AES-256, independently).

## 4. Why the inventory format is a plain JSON file

Real cloud environments expose certificates/keys/TLS configs through very
different APIs (AWS ACM + IAM + ELBv2, Azure Key Vault + Application
Gateway, GCP Certificate Manager, on-prem `vault` or `etcd`-backed PKI). To
keep the PoC provider-agnostic, this scanner operates on a normalized JSON
schema (`certificates`, `ssh_keys`, `tls_configs`) rather than calling any
SDK directly. `generate_mock_environment()` produces a file in that schema;
a real collector just needs to produce the same shape. This separation —
**collectors produce normalized inventory, the scanner only consumes it** —
is what makes the tool extensible to multiple clouds without touching the
classification logic.

## 5. Why severity is computed, not hand-assigned

Each classifier returns a `(status, severity, reason, recommendation)`
tuple computed from the *input data* rather than looked up from a static
table keyed by resource name. This means adding a new algorithm pattern
(e.g., a new PQC KEM) automatically gets correct severity and
recommendations everywhere it's used (certs, SSH keys, cipher suites)
without touching the report code.

Please give feedback to mailto://a.johnson@pocvisions on:
- Are the enumerated keys correctly identified and classified?
- Is the tool easy enough a tier 1 tech support technician can perform these audits on a scheduled basis?
- Does this help properly identify any shortfalls of an organization's "Quantum Readiness"?
- Any confusing parts or missing info?