# Key Attestation Root Policy

> Version: 1.0
> Status: FROZEN
> Last Updated: 2026-03-05

## Overview

Android Key Attestation uses a certificate chain rooted in Google's hardware attestation keys. This document defines the trust policy and root rotation schedule.

## Current Trust Roots

### Production Roots (2026)

| Root | Valid From | Valid Until | Fingerprint (SHA-256) |
|------|------------|-------------|----------------------|
| Google Hardware Attestation Root 1 | 2016-05-26 | 2036-05-24 | `EB...` (legacy) |
| Google Hardware Attestation Root 2 | 2024-01-01 | 2044-01-01 | `7A...` (current) |

### Root Certificate (Embedded)

Roots are **compiled into the application**, NOT fetched at runtime.

```kotlin
object AttestationRoots {
    val GOOGLE_ROOT_1 = """
        -----BEGIN CERTIFICATE-----
        MIIFYDCCA0igAwIBAgIJAOj6GWMU0...
        -----END CERTIFICATE-----
    """.trimIndent()

    val GOOGLE_ROOT_2 = """
        -----BEGIN CERTIFICATE-----
        MIICpDCCAkqgAwIBAgIKYQ...
        -----END CERTIFICATE-----
    """.trimIndent()

    val ALL_ROOTS = listOf(GOOGLE_ROOT_1, GOOGLE_ROOT_2)
}
```

## Root Rotation Schedule

### Timeline (2026)

```yaml
keyAttestationRootPolicy:
  legacyRootValidUntil: "2026-04-10"
  newRootValidFrom: "2026-02-01"
  rkpDeviceCutover: "2026-02-01"
  legacyOnlyDeviceCutoff: "2026-04-10"
  trustStoreUpdateDeadline: "2026-03-31"
```

### Phase 1: Dual Root Period (2026-02-01 to 2026-04-10)

- Both Root 1 and Root 2 are trusted
- New devices (RKP) use Root 2
- Legacy devices continue using Root 1
- **Action**: Update trust store to include Root 2

### Phase 2: Root 2 Only (2026-04-10+)

- Only Root 2 is trusted
- Legacy Root 1 devices rejected
- **Action**: Remove Root 1 from trust store (optional, can keep for audit)

### Emergency Rotation

If a root is compromised:

1. Google issues revocation notice
2. Platform adds root to blocklist within 24h
3. Affected evidence flagged for manual review
4. New evidence from compromised root rejected

## Verification Rules

### Certificate Chain Validation

```kotlin
fun verifyAttestationChain(chain: List<X509Certificate>): AttestationResult {
    // 1. Verify chain builds to trusted root
    val root = chain.last()
    if (root.subjectX500Principal !in TRUSTED_ROOTS) {
        return AttestationResult.UNTRUSTED_ROOT
    }

    // 2. Verify each certificate signature
    for (i in 0 until chain.size - 1) {
        val cert = chain[i]
        val issuer = chain[i + 1]
        if (!verifySignature(cert, issuer.publicKey)) {
            return AttestationResult.INVALID_SIGNATURE
        }
    }

    // 3. Check validity period
    val now = Date()
    for (cert in chain) {
        if (now.before(cert.notBefore) || now.after(cert.notAfter)) {
            return AttestationResult.EXPIRED_CERTIFICATE
        }
    }

    // 4. Parse attestation extension
    val leafCert = chain.first()
    val attestation = parseAttestationExtension(leafCert)

    // 5. Verify key properties
    if (attestation.securityLevel < SecurityLevel.TRUSTED_ENVIRONMENT) {
        return AttestationResult.WEAK_SECURITY_LEVEL
    }

    return AttestationResult.VALID
}
```

### Attestation Extension OID

```
Key Attestation Extension OID: 1.3.6.1.4.1.11129.2.1.17
```

### Required Attestation Properties

| Property | Requirement | Rationale |
|----------|-------------|-----------|
| `securityLevel` | >= TrustedEnvironment | Hardware-backed key required |
| `attestationSecurityLevel` | >= TrustedEnvironment | Attestation from secure hardware |
| `keyPurpose` | Sign | Key can sign sealHash |
| `algorithm` | EC/P-256 | ECDSA P-256 required |
| `noAuthRequired` | false | User presence required |

## Device Compatibility

### Supported Devices

| Category | Example | Support |
|----------|---------|---------|
| RKP (Remote Key Provisioning) | Pixel 6+, Samsung S22+ | Full support |
| StrongBox | Pixel 3+, Samsung S10+ | Full support |
| TEE-only | Older devices | Limited support |
| Software | Emulators | Rejected |

### Fallback Policy

For devices without hardware attestation:

1. **Option A (Strict)**: Reject device entirely
2. **Option B (Degraded)**: Accept with `credibilityLevel: LOW`
3. **Platform default**: Option A for production

## Trust Store Management

### Update Process

1. Attestation root changes announced by Google
2. Engineering reviews change
3. Trust store updated in codebase
4. App release with updated roots
5. Backend trust store synchronized

### No Runtime Fetching

```kotlin
// WRONG - Never do this:
// val roots = fetchRootsFromServer()

// CORRECT - Compile-time embedding:
val roots = AttestationRoots.ALL_ROOTS
```

**Rationale**: Runtime fetching creates MITM attack vector.

## Revocation Handling

### CRL/OCSP

Google does not publish CRL/OCSP for attestation roots.

Revocation handled via:
1. Google Security Blog announcements
2. Android Security Bulletins
3. Platform-maintained blocklist

### Blocklist Format

```json
{
  "version": 1,
  "updatedAt": "2026-03-05T00:00:00Z",
  "blockedCertificates": [
    {
      "serialNumber": "01:23:45:67:89:AB:CD:EF",
      "reason": "key_compromise",
      "blockedAt": "2026-03-01T00:00:00Z"
    }
  ],
  "blockedDevices": [
    {
      "attestationIdPattern": "manufacturer=CompromisedVendor",
      "reason": "factory_key_leak",
      "blockedAt": "2026-02-15T00:00:00Z"
    }
  ]
}
```

## Audit Requirements

- [ ] Trust store includes all current roots
- [ ] Legacy root removal scheduled after cutoff
- [ ] Blocklist update mechanism tested
- [ ] Certificate chain validation tested with known-good chains
- [ ] Rejection tested with tampered chains
- [ ] Security level enforcement tested
