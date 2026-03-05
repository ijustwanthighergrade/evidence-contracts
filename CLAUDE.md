# CLAUDE.md

This file provides guidance to Claude Code when working with the evidence-contracts repository.

## Project Overview

**evidence-contracts** is the specification and test vector repository for the Evidence Encryption Platform. It defines:
- JSON Schemas for manifest, event chain, and proof structures
- Cryptographic specifications (AAD, sealHash, nonce lifecycle)
- Cross-platform test vectors
- Reference implementations in Python, TypeScript, and Kotlin

This repo is consumed by:
- `noisecamara-app` (Android client)
- `evidence-platform` (Backend services)

## Repository Structure

```
evidence-contracts/
├── schemas/                    # JSON Schema definitions
│   ├── manifest.v2.schema.json # Evidence manifest structure
│   ├── event.v2.schema.json    # Event chain structure
│   └── proof.v1.schema.json    # Proof status and content
│
├── specs/                      # Technical specifications
│   ├── aad-format.md           # 60-byte AAD structure
│   ├── seal-hash.md            # sealHash computation (6 × 32 bytes)
│   ├── nonce-lifecycle.md      # DEK/nonce rules + backend validation
│   ├── canonical-json.md       # RFC 8785 JCS rules
│   ├── key-attestation-roots.md # Android Key Attestation policy
│   ├── proof-state-machine.md  # Proof states and SLA
│   ├── uuid-byte-order.md      # RFC4122 network byte order
│   └── version-compatibility.md # Read/write compatibility rules
│
├── test-vectors/               # Official test cases
│   ├── aad-computation.json    # 8 AAD test vectors
│   ├── nonce-generation.json   # 10 nonce test vectors
│   ├── seal-hash-10-cases.json # 10 sealHash test vectors
│   ├── canonical-json.json     # 15 JCS test vectors
│   └── inclusion-proof.json    # Merkle proof test vectors
│
├── reference-impl/
│   ├── python/                 # Python reference implementations
│   │   ├── aad_builder.py      # AAD construction
│   │   ├── seal_hash.py        # sealHash computation
│   │   ├── canonical_json.py   # RFC 8785 JCS
│   │   ├── merkle_tree.py      # Merkle root and proofs
│   │   └── verify_vectors.py   # Cross-platform verification
│   ├── typescript/             # TypeScript implementations
│   └── kotlin/                 # Kotlin implementations (TODO)
│
├── conformance-tests/          # Conformance test suites
│   └── nonce_conformance.py    # Nonce security tests
│
└── docs/                       # Additional documentation
    └── risk-assessment-and-mitigations.md
```

## Key Technical Concepts

### AAD (Additional Authenticated Data) - 60 bytes

```
Offset  Size  Field           Type
------  ----  -----           ----
0       1     aeadSuiteId     uint8 (0x01=AES-256-GCM)
1       1     hashSuiteId     uint8 (0x01=SHA-256)
2       16    evidenceId      UUID big-endian
18      8     chunkIndex      uint64 big-endian
26      2     manifestVer     uint16 big-endian
28      32    policyHash      bytes
```

### sealHash Computation

```
sealHash = SHA-256(
    manifestHash ||           # 32 bytes
    mediaPlaintextHash ||     # 32 bytes
    chunkMerkleRoot ||        # 32 bytes
    finalEventHash ||         # 32 bytes
    sessionBindingHash ||     # 32 bytes
    policyHash                # 32 bytes
)
Total input: 192 bytes
```

### Nonce Structure (12 bytes)

```
nonce = noncePrefix (4 bytes random) || chunkIndex (8 bytes big-endian)
```

**Critical Rules**:
- One DEK per evidence (never reuse)
- Same ciphertext for retries (never re-encrypt)
- Persist noncePrefix before any encryption

### Proof States

```
UPLOADED → PROVISIONAL → ANCHORED_TSA → ANCHORED_PENDING → FINALITY_REACHED
```

## Development Commands

```bash
# Run all Python tests
python reference-impl/python/aad_builder.py
python reference-impl/python/seal_hash.py
python reference-impl/python/verify_vectors.py
python reference-impl/python/canonical_json.py
python reference-impl/python/merkle_tree.py
python conformance-tests/nonce_conformance.py

# Run TypeScript tests
cd reference-impl/typescript && npm test

# Validate schemas (requires ajv-cli)
npm install -g ajv-cli ajv-formats
ajv compile -s schemas/manifest.v2.schema.json --spec=draft2020 -c ajv-formats
```

## CI Pipeline

GitHub Actions runs on every push to master:

1. **Schema Validation** - Validates all JSON schemas with ajv
2. **Python Tests** - Runs all Python test scripts
3. **TypeScript Tests** - Runs npm test
4. **Cross-Platform Verification** - Ensures implementations produce identical results

## Adding New Test Vectors

1. Add test case to appropriate JSON file in `test-vectors/`
2. Compute expected values using Python reference implementation
3. Update `verify_vectors.py` if needed
4. Run CI to ensure cross-platform consistency

## Spec Change Process

1. Update spec document in `specs/`
2. Update relevant JSON schema if structure changes
3. Add/update test vectors
4. Update reference implementations
5. Run all tests locally
6. Submit PR with clear description of changes

## Security Considerations

### P0 Risks (Must be addressed)

| Risk | Mitigation | Status |
|------|------------|--------|
| Nonce reuse | Conformance tests + backend validation | ✅ Mitigated |
| Key Attestation rotation | Dual root validation logic | ✅ Mitigated |

### Implementation Checklist

**App-side**:
- [ ] noncePrefix generated with SecureRandom
- [ ] noncePrefix persisted before encryption
- [ ] Encrypted chunks persisted before upload
- [ ] Retry reads from storage, never re-encrypts
- [ ] DEK in Android Keystore, bound to evidenceId

**Backend-side**:
- [ ] Validates chunk hash consistency
- [ ] Validates DEK-evidenceId binding
- [ ] Logs all security events
- [ ] Monitoring alerts configured

## Version Compatibility

- **Manifest v2**: Read compatibility guaranteed for 5+ years (until 2031-03)
- **Breaking changes**: Require major version bump
- **New optional fields**: Allowed in minor versions

## Related Repositories

| Repo | Purpose |
|------|---------|
| `noisecamara-app` | Android evidence collection app |
| `evidence-platform` | Backend API, storage, anchoring |

## Contact

For specification questions or issues, open a GitHub issue in this repository.
