# Nonce Lifecycle Specification

> Version: 1.0
> Status: FROZEN
> Last Updated: 2026-03-05

## Overview

AES-GCM security depends critically on nonce uniqueness per (key, nonce) pair. This document defines nonce generation, usage, and retry rules.

## Nonce Structure (12 bytes)

```
nonce = noncePrefix || chunkIndex

Where:
  noncePrefix: 4 bytes (random, per-evidence)
  chunkIndex:  8 bytes (big-endian uint64)
```

## Lifecycle Rules

### 1. DEK Generation

```
One DEK per evidence, NEVER reuse across evidence packages
```

- Generate fresh AES-256 key for each evidence
- DEK is wrapped using server KEK before storage
- DEK lifetime = evidence lifetime

### 2. Nonce Prefix Generation

```kotlin
fun generateNoncePrefix(): ByteArray {
    val prefix = ByteArray(4)
    SecureRandom().nextBytes(prefix)
    return prefix
}
```

- Generate once when starting evidence capture
- Store immediately in persistent storage
- Write to `manifest.encryption.noncePrefix`
- NEVER regenerate for the same evidence

### 3. Nonce Construction

```kotlin
fun buildNonce(noncePrefix: ByteArray, chunkIndex: Long): ByteArray {
    require(noncePrefix.size == 4)
    require(chunkIndex >= 0)

    val nonce = ByteArray(12)
    System.arraycopy(noncePrefix, 0, nonce, 0, 4)

    val buffer = ByteBuffer.allocate(8)
    buffer.order(ByteOrder.BIG_ENDIAN)
    buffer.putLong(chunkIndex)
    System.arraycopy(buffer.array(), 0, nonce, 4, 8)

    return nonce
}
```

### 4. Chunk Limits

| Metric | Limit | Rationale |
|--------|-------|-----------|
| Max chunks per evidence | 2^64 - 1 | chunkIndex overflow |
| Practical limit | ~125,000 | 1 TB @ 8 MB chunks |
| Recommended max | 10,000 | 80 GB, ~2h 4K video |

## Retry Rules

### Critical: Same Ciphertext for Retries

```
If upload fails, retry with THE SAME ciphertext, NOT re-encrypted
```

**Why**: Re-encrypting with same nonce leaks XOR of plaintexts.

### Implementation Requirements

1. **Persist encrypted chunks** before upload attempt
2. **Track upload status** per chunk (pending/uploaded/confirmed)
3. **Retry from disk** on failure, not from memory
4. **Confirm deletion** only after server acknowledgment

### State Machine

```
ENCRYPTING → ENCRYPTED_PENDING → UPLOADING → UPLOADED → CONFIRMED
                    ↑                 |
                    └────── retry ────┘
```

### Pseudocode

```kotlin
class ChunkUploader(
    private val storage: ChunkStorage,
    private val api: UploadApi
) {
    suspend fun uploadChunk(evidenceId: UUID, chunkIndex: Int): Result {
        // 1. Check if already encrypted
        val cached = storage.getEncryptedChunk(evidenceId, chunkIndex)

        val ciphertext = if (cached != null) {
            // Retry: use existing ciphertext
            cached
        } else {
            // First attempt: encrypt and persist
            val plaintext = readChunkFromMedia(chunkIndex)
            val encrypted = encryptChunk(plaintext, chunkIndex)
            storage.saveEncryptedChunk(evidenceId, chunkIndex, encrypted)
            encrypted
        }

        // 2. Upload (may retry multiple times)
        val result = api.uploadWithRetry(evidenceId, chunkIndex, ciphertext)

        // 3. Only delete after confirmation
        if (result.isConfirmed) {
            storage.deleteEncryptedChunk(evidenceId, chunkIndex)
        }

        return result
    }
}
```

## Lost Nonce Prefix Recovery

**There is no recovery**. If `noncePrefix` is lost before manifest upload:

1. Evidence MUST be abandoned
2. User notified to re-record
3. Partial uploads cleaned up

### Prevention

- Write `noncePrefix` to persistent storage immediately after generation
- Include in manifest draft before any encryption
- Backup strategy: store in SQLite + SharedPreferences

## Nonce Collision Analysis

### Birthday Bound

With 4-byte random prefix:
- 2^32 possible prefixes
- Birthday collision at ~2^16 = 65,536 evidence packages
- Per-device risk: negligible (users don't create 65K+ evidence)
- Platform-wide: monitor for anomalies

### Mitigation

Each evidence has unique DEK, so nonce collision across evidence is harmless:

```
Evidence A: (DEK_A, nonce_prefix_A || chunk_0)
Evidence B: (DEK_B, nonce_prefix_B || chunk_0)

Even if nonce_prefix_A == nonce_prefix_B, DEK_A ≠ DEK_B → safe
```

## Backend Validation Rules

### Chunk Upload Verification

```typescript
async function validateChunkUpload(
    evidenceId: string,
    chunkIndex: number,
    ciphertext: Buffer
): Promise<ValidationResult> {
    const existingChunk = await chunkRepository.find(evidenceId, chunkIndex);

    if (existingChunk) {
        const existingHash = existingChunk.ciphertextHash;
        const newHash = sha256(ciphertext);

        if (!existingHash.equals(newHash)) {
            // CRITICAL: Same chunk index, different content = potential nonce reuse
            await securityLog.alert({
                type: 'POTENTIAL_NONCE_REUSE',
                evidenceId,
                chunkIndex,
                severity: 'CRITICAL'
            });

            return {
                valid: false,
                error: 'CHUNK_CONTENT_MISMATCH'
            };
        }

        // Idempotent: same content, accept
        return { valid: true, idempotent: true };
    }

    return { valid: true, idempotent: false };
}
```

### DEK Binding Verification

```typescript
async function validateDekBinding(
    evidenceId: string,
    wrappedDek: Buffer
): Promise<ValidationResult> {
    const dekMetadata = await kms.unwrapKey(wrappedDek);

    // Verify DEK is bound to this evidence
    if (dekMetadata.boundEvidenceId !== evidenceId) {
        return { valid: false, error: 'DEK_EVIDENCE_MISMATCH' };
    }

    // Check DEK hasn't been used elsewhere
    const existing = await evidenceRepository.findByDekId(dekMetadata.dekId);
    if (existing && existing.id !== evidenceId) {
        await securityLog.alert({
            type: 'DEK_REUSE_ATTEMPT',
            severity: 'CRITICAL'
        });
        return { valid: false, error: 'DEK_ALREADY_USED' };
    }

    return { valid: true };
}
```

## Security Monitoring

### Critical Metrics

| Metric | Alert Condition | Severity |
|--------|-----------------|----------|
| `chunk_hash_mismatch_total` | > 0 | P0 |
| `dek_reuse_attempt_total` | > 0 | P0 |
| `nonce_prefix_recovery_total` | > 10/day | P2 |
| `chunk_retry_ratio` | > 20% | P2 |

### Alert Rules

```yaml
groups:
  - name: nonce_security
    rules:
      - alert: ChunkHashMismatch
        expr: increase(chunk_hash_mismatch_total[5m]) > 0
        labels:
          severity: critical
        annotations:
          summary: "Potential nonce reuse detected"

      - alert: DekReuseAttempt
        expr: increase(dek_reuse_attempt_total[5m]) > 0
        labels:
          severity: critical
```

## Conformance Tests

### Required App-Side Tests

```python
def test_nonce_uniqueness():
    """All nonces within evidence must be unique"""
    nonce_prefix = generate_nonce_prefix()
    nonces = set()

    for i in range(10000):
        nonce = build_nonce(nonce_prefix, i)
        assert nonce not in nonces
        nonces.add(nonce)

def test_retry_same_ciphertext():
    """Retry must return identical ciphertext"""
    encryptor = ChunkEncryptor(dek, nonce_prefix, storage)

    first = encryptor.encrypt_chunk(0, b"data")
    retry = encryptor.get_for_retry(0)

    assert first.ciphertext == retry.ciphertext

def test_reject_reencryption():
    """Must reject attempt to re-encrypt same chunk"""
    encryptor = ChunkEncryptor(dek, nonce_prefix, storage)
    encryptor.encrypt_chunk(0, b"original")

    with pytest.raises(ChunkAlreadyEncryptedException):
        encryptor.encrypt_chunk(0, b"different")

def test_nonce_prefix_persisted_first():
    """noncePrefix must be persisted before first encryption"""
    storage = MockStorage()
    encryptor = ChunkEncryptor(dek, nonce_prefix, storage)
    encryptor.encrypt_chunk(0, b"test")

    assert storage.nonce_prefix_save_time < storage.first_encrypt_time
```

### Required Backend Tests

```typescript
describe('Nonce Security', () => {
    it('rejects chunk with mismatched content', async () => {
        await uploadChunk(evidenceId, 0, Buffer.from('original'));
        const result = await uploadChunk(evidenceId, 0, Buffer.from('different'));

        expect(result.status).toBe(409);
        expect(result.error).toBe('CHUNK_CONTENT_MISMATCH');
    });

    it('accepts identical retry', async () => {
        const content = Buffer.from('test');
        await uploadChunk(evidenceId, 0, content);
        const result = await uploadChunk(evidenceId, 0, content);

        expect(result.status).toBe(200);
        expect(result.idempotent).toBe(true);
    });

    it('rejects DEK reuse', async () => {
        const dek = generateDek();
        await createEvidence('ev-1', dek);
        const result = await createEvidence('ev-2', dek);

        expect(result.error).toBe('DEK_ALREADY_USED');
    });
});
```

## Security Checklist

### App Implementation

- [ ] `noncePrefix` generated with `SecureRandom`
- [ ] `noncePrefix` persisted before any encryption
- [ ] Encrypted chunks persisted before upload
- [ ] Retry reads from storage, not re-encrypts
- [ ] DEK stored in Android Keystore
- [ ] DEK bound to single `evidenceId`

### Backend Implementation

- [ ] Validates chunk hash consistency
- [ ] Validates DEK-evidenceId binding
- [ ] Logs all security events
- [ ] Monitoring alerts configured
- [ ] Idempotent upload handling

## Test Vectors

See `test-vectors/nonce-generation.json` for official test cases.
