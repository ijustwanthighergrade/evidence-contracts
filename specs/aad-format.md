# AAD Format Specification

> Version: 1.0
> Status: FROZEN
> Last Updated: 2026-03-05

## Overview

Additional Authenticated Data (AAD) is bound to each encrypted chunk via AES-GCM authentication. This document defines the exact 60-byte AAD structure.

## Binary Format (60 bytes, fixed)

```
Offset  Size  Field           Type        Description
------  ----  -----           ----        -----------
0       1     aeadSuiteId     uint8       AEAD algorithm identifier
1       1     hashSuiteId     uint8       Hash algorithm identifier
2       16    evidenceId      bytes[16]   RFC4122 UUID, network byte order
18      8     chunkIndex      uint64_be   Big-endian chunk index (0-based)
26      2     manifestVer     uint16_be   Manifest version (e.g., 0x0002)
28      32    policyHash      bytes[32]   SHA-256 of policy document
------
Total: 60 bytes
```

## Field Definitions

### aeadSuiteId (1 byte)

| Value | Algorithm       | Notes |
|-------|-----------------|-------|
| 0x01  | AES-256-GCM     | Default, NIST SP 800-38D |
| 0x02  | AES-256-GCM-SIV | Alternative, nonce-misuse resistant |

### hashSuiteId (1 byte)

| Value | Algorithm | Notes |
|-------|-----------|-------|
| 0x01  | SHA-256   | Default, FIPS 180-4 |
| 0x02  | SHA-3-256 | Alternative |

### evidenceId (16 bytes)

- **Format**: RFC4122 UUID
- **Byte Order**: Network byte order (big-endian)
- **Warning**: Do NOT use .NET `Guid.ToByteArray()` which returns little-endian

Example:
```
UUID string: "550e8400-e29b-41d4-a716-446655440000"
Bytes (hex): 55 0e 84 00 e2 9b 41 d4 a7 16 44 66 55 44 00 00
```

### chunkIndex (8 bytes)

- **Type**: Unsigned 64-bit integer
- **Byte Order**: Big-endian
- **Range**: 0 to 2^64-1 (practical limit: ~125,000 chunks @ 8MB = 1TB)

### manifestVer (2 bytes)

- **Type**: Unsigned 16-bit integer
- **Byte Order**: Big-endian
- **Example**: Version 2.0 = 0x0002

### policyHash (32 bytes)

- **Algorithm**: SHA-256
- **Input**: Canonical JSON (JCS) of policy document
- **Purpose**: Binds evidence to capture policy

## Construction Pseudocode

```kotlin
fun buildAAD(
    aeadSuiteId: Byte,
    hashSuiteId: Byte,
    evidenceId: UUID,
    chunkIndex: Long,
    manifestVer: Int,
    policyHash: ByteArray
): ByteArray {
    require(policyHash.size == 32)

    val buffer = ByteBuffer.allocate(60)
    buffer.order(ByteOrder.BIG_ENDIAN)

    buffer.put(aeadSuiteId)                    // offset 0
    buffer.put(hashSuiteId)                    // offset 1
    buffer.put(uuidToNetworkBytes(evidenceId)) // offset 2-17
    buffer.putLong(chunkIndex)                 // offset 18-25
    buffer.putShort(manifestVer.toShort())     // offset 26-27
    buffer.put(policyHash)                     // offset 28-59

    return buffer.array()
}

fun uuidToNetworkBytes(uuid: UUID): ByteArray {
    val buffer = ByteBuffer.allocate(16)
    buffer.order(ByteOrder.BIG_ENDIAN)
    buffer.putLong(uuid.mostSignificantBits)
    buffer.putLong(uuid.leastSignificantBits)
    return buffer.array()
}
```

## Verification

AAD verification MUST:
1. Reconstruct AAD from manifest fields
2. Compare byte-for-byte with expected value
3. Reject if any byte differs

## Security Considerations

- AAD is authenticated but NOT encrypted
- Changing any AAD byte causes GCM decryption to fail
- evidenceId in AAD prevents chunk substitution attacks
- chunkIndex prevents chunk reordering
- policyHash binds evidence to capture rules

## Test Vectors

See `test-vectors/aad-computation.json` for official test cases.
