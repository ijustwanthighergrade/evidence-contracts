# Evidence Contracts

Specification repository for the **Audio-Video Evidence Preservation Platform**.

This repo defines the contracts between:
- **noisecamara-app**: Android evidence collection app
- **evidence-platform**: Backend API, storage, and anchoring services

## Contents

```
evidence-contracts/
├── schemas/                    # JSON Schema definitions
│   ├── manifest.v2.schema.json # Evidence manifest (frozen)
│   ├── event.v2.schema.json    # Event chain structure
│   ├── proof.v1.schema.json    # Proof status and anchoring
│   └── openapi/                # REST API specifications
│
├── specs/                      # Technical specifications
│   ├── aad-format.md           # AAD 60-byte structure
│   ├── seal-hash.md            # sealHash computation
│   ├── nonce-lifecycle.md      # DEK/nonce rules
│   ├── proof-state-machine.md  # State transitions & SLA
│   └── ...
│
├── test-vectors/               # Official test cases
│   ├── seal-hash-10-cases.json
│   ├── aad-computation.json
│   └── ...
│
├── reference-impl/             # Reference implementations
│   ├── kotlin/                 # Android
│   ├── typescript/             # Backend
│   └── python/                 # Verification tools
│
├── conformance-tests/          # Mandatory tests
│   ├── app-conformance/
│   ├── backend-conformance/
│   └── cross-platform/
│
└── ci/                         # CI scripts
```

## Version Policy

- **manifest.v2**: Read compatibility guaranteed for 5+ years (until 2031-03)
- Breaking changes require major version bump
- New optional fields allowed in minor versions

## Quick Links

- [Manifest Schema](schemas/manifest.v2.schema.json)
- [AAD Format Spec](specs/aad-format.md)
- [sealHash Spec](specs/seal-hash.md)
- [Proof State Machine](specs/proof-state-machine.md)
- [Test Vectors](test-vectors/)

## License

MIT
