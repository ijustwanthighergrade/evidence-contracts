# Proof State Machine Specification

> Version: 1.0
> Status: FROZEN
> Last Updated: 2026-03-05

## Overview

Evidence progresses through multiple proof states, from initial upload to final public chain confirmation. This document defines states, transitions, and SLAs.

## State Diagram

```
                    ┌─────────────┐
                    │   CREATED   │
                    └──────┬──────┘
                           │ upload complete
                           ▼
                    ┌─────────────┐
                    │  UPLOADED   │ ← WORM storage confirmed
                    └──────┬──────┘
                           │ log entry created
                           ▼
                    ┌─────────────┐
                    │ PROVISIONAL │ ← Transparency log entry + STH
                    └──────┬──────┘
                           │ TSA timestamp obtained
                           ▼
                    ┌──────────────┐
                    │ ANCHORED_TSA │ ← RFC 3161 timestamp
                    └──────┬───────┘
                           │ batch submitted to chain
                           ▼
                  ┌──────────────────┐
                  │ ANCHORED_PENDING │ ← Tx submitted, awaiting confirm
                  └────────┬─────────┘
                           │ sufficient confirmations
                           ▼
                  ┌──────────────────┐
                  │ FINALITY_REACHED │ ← Immutable proof complete
                  └──────────────────┘

        ┌──────────────────┐
        │  FAILED_RETRYING │ ← Any transition failure
        └──────────────────┘
              ↑     │
              │     │ retry success
              │     ▼
              └─ [previous state]
```

## State Definitions

### UPLOADED

Evidence ciphertext stored in WORM storage.

| Field | Description |
|-------|-------------|
| storageReceipt | WORM storage ETag or receipt |
| uploadedAt | ISO 8601 timestamp |
| storageLocation | Storage path (internal) |

**Guarantees**:
- Evidence is immutable in storage
- Cannot be overwritten or deleted
- Retained for policy duration (default: 10 years)

### PROVISIONAL

Logged in transparency log with signed tree head.

| Field | Description |
|-------|-------------|
| logEntryId | Unique entry identifier |
| signedTreeHead | STH at time of inclusion |
| provisionalAt | ISO 8601 timestamp |

**Guarantees**:
- Existence can be proven via inclusion proof
- Log operator cannot remove without detection
- Provides provisional timestamp

### ANCHORED_TSA

RFC 3161 timestamp obtained from trusted TSA.

| Field | Description |
|-------|-------------|
| tsaToken | Base64-encoded timestamp token |
| tsaAt | Timestamp from TSA |
| tsaAuthority | TSA provider URL |

**Guarantees**:
- Legally recognized timestamp
- Independent third-party attestation
- Admissible in many jurisdictions

### ANCHORED_PENDING

Submitted to public blockchain, awaiting confirmation.

| Field | Description |
|-------|-------------|
| txId | Blockchain transaction ID |
| submittedAt | Submission time |
| chain | "bitcoin", "ethereum", or "ots" |

**Note**: NOT final until confirmations reach threshold.

### FINALITY_REACHED

Sufficient blockchain confirmations achieved.

| Field | Description |
|-------|-------------|
| txId | Blockchain transaction ID |
| blockHeight | Block number |
| confirmations | Number of confirmations |
| finalizedAt | When threshold reached |
| inclusionProof | Merkle proof to batch root |

**Guarantees**:
- Computationally infeasible to revert
- Publicly verifiable by anyone
- Evidence existed before finalizedAt

**Confirmation Thresholds**:
| Chain | Threshold | Rationale |
|-------|-----------|-----------|
| Bitcoin | 6 blocks | ~1 hour, industry standard |
| Ethereum | 32 epochs | Finality in PoS |
| OpenTimestamps | 1 block | Inherits Bitcoin security |

### FAILED_RETRYING

Transition failure with retry in progress.

| Field | Description |
|-------|-------------|
| failureReason | Error description |
| retryCount | Number of attempts |
| nextRetryAt | Scheduled retry time |
| lastAttemptAt | Last attempt time |

## SLA Definitions

### Latency Targets

| Transition | p50 | p95 | p99 | Alert Threshold |
|------------|-----|-----|-----|-----------------|
| → UPLOADED | < 2s | < 5s | < 10s | > 30s |
| → PROVISIONAL | < 3s | < 8s | < 15s | > 60s |
| → ANCHORED_TSA | < 30s | < 3min | < 5min | > 10min |
| → FINALITY_REACHED | < 2h | < 6h | < 24h | > 24h |

### Alert Rules

| Condition | Severity | Action |
|-----------|----------|--------|
| ANCHORED_PENDING > 24h | P1 | Page on-call |
| FAILED_RETRYING count ≥ 3 | P0 | Immediate manual intervention |
| Any transition > p99 | P2 | Investigation ticket |
| Batch size < 10 for 4h | P3 | Monitor batching efficiency |

## Batch Anchoring

Evidence is anchored in batches to amortize chain costs.

### Batch Parameters

| Parameter | Value | Notes |
|-----------|-------|-------|
| Batch interval | 15 min | Maximum wait time |
| Min batch size | 1 | Anchor immediately if aged |
| Max batch size | 1000 | Split if exceeded |
| Max evidence age | 30 min | Force batch if any item aged |

### Merkle Tree Construction

```
              batchRoot
              /       \
         hash01       hash23
         /   \        /   \
     hash0  hash1  hash2  hash3
       |      |      |      |
   seal0  seal1  seal2  seal3
```

Each leaf is an evidence's `sealHash`.

### Inclusion Proof

```json
{
  "leafIndex": 1,
  "leafHash": "abc123...",
  "proof": [
    {"position": "left", "hash": "def456..."},
    {"position": "right", "hash": "789abc..."}
  ],
  "root": "final_root..."
}
```

## API Endpoints

### GET /api/v2/evidence/{id}/proof

Returns current proof status and all available proofs.

### GET /api/v2/evidence/{id}/proof/history

Returns full state transition history.

### POST /api/v2/evidence/{id}/proof/refresh

Force refresh proof status (rate limited).

## Monitoring Metrics

| Metric | Type | Labels |
|--------|------|--------|
| evidence_proof_state | Gauge | state |
| evidence_state_transition_duration_ms | Histogram | from, to |
| evidence_state_transition_failures | Counter | from, to, reason |
| anchor_batch_size | Histogram | chain |
| anchor_confirmations | Gauge | chain, tx_id |

## Test Scenarios

1. Happy path: CREATED → FINALITY_REACHED in < 6h
2. TSA failure: Retry 3x, then P0 alert
3. Chain congestion: Extended ANCHORED_PENDING
4. Log corruption: Detect via inclusion proof failure
5. Batch merge: Multiple evidence in single anchor
