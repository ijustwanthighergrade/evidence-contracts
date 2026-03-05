# Offline Verification Bundle Format

> Version: 1.0
> Status: FROZEN
> Last Updated: 2026-03-05

## Overview

The offline verification bundle is a self-contained ZIP archive that allows third parties to verify evidence integrity without network access.

## File Name

```
{evidenceId}-verification-bundle.zip
```

Example: `550e8400-e29b-41d4-a716-446655440000-verification-bundle.zip`

## Archive Contents

```
{evidenceId}-verification-bundle/
├── manifest.json              # Canonical JSON (JCS)
├── manifest.sig               # ECDSA P-256 signature (DER)
├── attestation-chain.pem      # Key Attestation certificate chain
├── event-chain.json           # Complete event chain
├── transparency-log-proof.json
├── tsa-token.tsr              # RFC 3161 timestamp token
├── anchor-proof.json          # Blockchain anchor proof
├── verification-report.json   # Platform-generated report
├── VERIFY.md                  # Human-readable guide
└── tools/
    └── verify.py              # Python verification script
```

## File Specifications

### manifest.json

The evidence manifest in RFC 8785 JSON Canonicalization Scheme (JCS) format.

```json
{
  "version": "2.0",
  "evidenceId": "550e8400-e29b-41d4-a716-446655440000",
  "createdAt": "2026-03-05T10:30:00Z",
  ...
}
```

### manifest.sig

DER-encoded ECDSA P-256 signature over `sealHash`.

```
Binary file (70-72 bytes typically)
```

Verification:
```python
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

public_key.verify(sig, seal_hash, ec.ECDSA(hashes.SHA256()))
```

### attestation-chain.pem

PEM-encoded X.509 certificate chain from Android Key Attestation.

```
-----BEGIN CERTIFICATE-----
MIICnDCC...  (device certificate)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICqDCC...  (intermediate)
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIFYDCC...  (Google root)
-----END CERTIFICATE-----
```

### event-chain.json

Complete event history with hash chain.

```json
{
  "version": "2.0",
  "evidenceId": "550e8400-e29b-41d4-a716-446655440000",
  "events": [
    {
      "eventId": "...",
      "eventType": "CAPTURE_STARTED",
      "timestamp": "2026-03-05T10:00:00Z",
      "prevHash": "0000000000000000000000000000000000000000000000000000000000000000",
      "eventHash": "abc123...",
      "payload": {...}
    },
    ...
  ],
  "finalEventHash": "xyz789..."
}
```

### transparency-log-proof.json

Inclusion proof in transparency log.

```json
{
  "logEntryId": "12345",
  "signedTreeHead": {
    "treeSize": 1000000,
    "rootHash": "abc123...",
    "timestamp": "2026-03-05T10:35:00Z",
    "signature": "base64..."
  },
  "inclusionProof": {
    "leafIndex": 999999,
    "hashes": ["hash1", "hash2", "hash3"]
  }
}
```

### tsa-token.tsr

RFC 3161 TimeStampResp in DER format.

Verification:
```bash
openssl ts -verify -in tsa-token.tsr -data seal_hash.bin -CAfile tsa_root.pem
```

### anchor-proof.json

Blockchain anchoring proof.

```json
{
  "chain": "bitcoin",
  "txId": "abc123def456...",
  "blockHeight": 850000,
  "confirmations": 100,
  "finalizedAt": "2026-03-05T12:00:00Z",
  "batchMerkleRoot": "root123...",
  "inclusionProof": {
    "leafIndex": 42,
    "merkleProof": ["hash1", "hash2", "hash3"]
  }
}
```

### verification-report.json

Platform-generated verification summary.

```json
{
  "generatedAt": "2026-03-05T14:00:00Z",
  "evidenceId": "550e8400-e29b-41d4-a716-446655440000",
  "verdict": {
    "status": "VALID",
    "credibilityLevel": "HIGH"
  },
  "checks": [
    {"name": "seal_hash", "status": "PASS"},
    {"name": "device_signature", "status": "PASS"},
    {"name": "attestation_chain", "status": "PASS"},
    {"name": "event_chain_integrity", "status": "PASS"},
    {"name": "transparency_log", "status": "PASS"},
    {"name": "tsa_timestamp", "status": "PASS"},
    {"name": "blockchain_anchor", "status": "PASS"}
  ]
}
```

### VERIFY.md

Human-readable verification instructions.

```markdown
# Evidence Verification Guide

## Evidence ID
550e8400-e29b-41d4-a716-446655440000

## Quick Verification

1. Run the included verification script:
   ```
   python tools/verify.py
   ```

2. Or verify manually:
   - Recompute sealHash from manifest
   - Verify device signature
   - Check attestation chain
   - Verify transparency log inclusion
   - Verify TSA timestamp
   - Verify blockchain anchor

## Expected Results
- All checks should PASS
- Credibility level: HIGH
...
```

## Verification Requirements

A valid bundle MUST pass all these checks:

1. **sealHash Verification**
   - Recompute from manifest components
   - Match with `manifest.integrity.sealHash`

2. **Device Signature**
   - Verify `manifest.sig` against `sealHash`
   - Using public key from attestation chain

3. **Attestation Chain**
   - Verify certificate chain to known root
   - Check key usage constraints

4. **Event Chain Integrity**
   - Verify each event links to previous
   - `finalEventHash` matches last event

5. **Transparency Log**
   - Verify inclusion proof against STH
   - STH signature valid

6. **TSA Timestamp**
   - RFC 3161 token valid
   - Timestamp matches expected time

7. **Blockchain Anchor**
   - Transaction exists on chain
   - Merkle proof valid
   - Sufficient confirmations

## Security Considerations

- Bundle can be distributed publicly
- Contains no encryption keys
- Media content NOT included
- Verifier needs only bundle + trusted roots
