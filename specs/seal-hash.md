# sealHash Specification

> Version: 1.0
> Status: FROZEN
> Last Updated: 2026-03-05

## Overview

The `sealHash` is a cryptographic binding that ties together all components of an evidence package. It serves as the signing target for device signatures.

## Formula

```
sealHash = SHA-256(
    manifestHash        ||   # 32 bytes
    mediaPlaintextHash  ||   # 32 bytes
    chunkMerkleRoot     ||   # 32 bytes
    finalEventHash      ||   # 32 bytes
    sessionBindingHash  ||   # 32 bytes
    policyHash               # 32 bytes
)
```

**Total input**: 192 bytes (6 × 32-byte hashes)
**Output**: 32 bytes (SHA-256)

## Component Definitions

### manifestHash (32 bytes)

```
manifestHash = SHA-256(JCS(manifest_without_integrity))
```

- Remove `integrity` field from manifest before hashing
- Apply RFC 8785 JSON Canonicalization Scheme (JCS)
- Hash the canonical UTF-8 bytes

### mediaPlaintextHash (32 bytes)

```
mediaPlaintextHash = SHA-256(original_media_bytes)
```

- Hash of the original, unencrypted media file
- Stored in `manifest.media.plaintextHash`

### chunkMerkleRoot (32 bytes)

```
chunkHashes = [SHA-256(ciphertext_chunk_0), SHA-256(ciphertext_chunk_1), ...]
chunkMerkleRoot = MerkleRoot(chunkHashes)
```

- Each chunk's ciphertext (including GCM tag) is hashed
- Merkle tree built from chunk hashes
- Stored in `manifest.encryption.chunkMerkleRoot`

### finalEventHash (32 bytes)

```
finalEventHash = eventChain.events[last].eventHash
```

- Hash of the final event in the event chain
- Links the entire event history to the seal

### sessionBindingHash (32 bytes)

```
sessionBindingHash = SHA-256(
    sessionId           ||   # 16 bytes (UUID, network order)
    serverIssuedAtUtc   ||   # 8 bytes (Unix epoch ms, big-endian)
    appSignatureDigest  ||   # 32 bytes
    deviceKeyId              # UTF-8 bytes, length-prefixed
)
```

Where `deviceKeyId` is length-prefixed:
```
[2 bytes: length in big-endian] || [UTF-8 bytes of deviceKeyId]
```

### policyHash (32 bytes)

```
policyHash = SHA-256(JCS(policy_document))
```

- Same value used in AAD
- Stored in `manifest.session.policyHash`

## Computation Pseudocode

```kotlin
fun computeSealHash(
    manifest: Manifest,
    mediaPlaintextHash: ByteArray,
    chunkMerkleRoot: ByteArray,
    finalEventHash: ByteArray
): ByteArray {
    // 1. Compute manifestHash (without integrity field)
    val manifestWithoutIntegrity = manifest.copy(integrity = null)
    val manifestJson = JCS.canonicalize(manifestWithoutIntegrity)
    val manifestHash = SHA256.hash(manifestJson.toByteArray(Charsets.UTF_8))

    // 2. Compute sessionBindingHash
    val sessionBinding = ByteBuffer.allocate(58 + deviceKeyIdBytes.size)
    sessionBinding.order(ByteOrder.BIG_ENDIAN)
    sessionBinding.put(uuidToNetworkBytes(manifest.session.sessionId))
    sessionBinding.putLong(manifest.session.serverIssuedAt.toEpochMilli())
    sessionBinding.put(hexToBytes(manifest.device.appSignatureDigest))
    sessionBinding.putShort(deviceKeyIdBytes.size.toShort())
    sessionBinding.put(deviceKeyIdBytes)
    val sessionBindingHash = SHA256.hash(sessionBinding.array())

    // 3. Concatenate all components (192 bytes)
    val sealInput = ByteBuffer.allocate(192)
    sealInput.put(manifestHash)           // 0-31
    sealInput.put(mediaPlaintextHash)     // 32-63
    sealInput.put(chunkMerkleRoot)        // 64-95
    sealInput.put(finalEventHash)         // 96-127
    sealInput.put(sessionBindingHash)     // 128-159
    sealInput.put(hexToBytes(manifest.session.policyHash)) // 160-191

    // 4. Final hash
    return SHA256.hash(sealInput.array())
}
```

## Verification

To verify a sealHash:

1. Recompute each component hash from source data
2. Concatenate in exact order specified
3. Compute SHA-256 of concatenation
4. Compare with `manifest.integrity.sealHash`

**Important**: Use constant-time comparison to prevent timing attacks.

## Security Properties

| Property | Guarantee |
|----------|-----------|
| Manifest integrity | manifestHash binds all metadata |
| Media integrity | mediaPlaintextHash binds original content |
| Ciphertext integrity | chunkMerkleRoot binds encrypted form |
| History integrity | finalEventHash binds event chain |
| Session binding | sessionBindingHash binds to server session |
| Policy binding | policyHash binds to capture rules |

## Test Vectors

See `test-vectors/seal-hash-10-cases.json` for official test cases.
