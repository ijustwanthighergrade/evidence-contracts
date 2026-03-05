# Version Compatibility Specification

> Version: 1.0
> Status: FROZEN
> Last Updated: 2026-03-05

## Overview

This document defines compatibility rules for manifest versions, ensuring long-term evidence readability while allowing controlled evolution.

## Version Numbering

### Semantic Versioning

```
MAJOR.MINOR

Example: 2.0, 2.1, 3.0
```

| Component | Change Type | Impact |
|-----------|-------------|--------|
| MAJOR | Breaking change | New reader required |
| MINOR | Additive change | Backward compatible |

### Current Versions

| Schema | Version | Status |
|--------|---------|--------|
| manifest | 2.0 | Active |
| event | 2.0 | Active |
| proof | 1.0 | Active |

## Compatibility Matrix

### Read Compatibility

"Can reader version X read manifest version Y?"

| Reader ↓ / Manifest → | 1.0 | 2.0 | 2.1 | 3.0 |
|-----------------------|-----|-----|-----|-----|
| 1.0 | ✓ | ✗ | ✗ | ✗ |
| 2.0 | ✓* | ✓ | ✗ | ✗ |
| 2.1 | ✓* | ✓ | ✓ | ✗ |
| 3.0 | ✓* | ✓ | ✓ | ✓ |

`*` = Legacy support mode

### Write Compatibility

"Can writer version X produce manifest version Y?"

| Writer ↓ / Manifest → | 1.0 | 2.0 | 2.1 | 3.0 |
|-----------------------|-----|-----|-----|-----|
| 1.0 | ✓ | ✗ | ✗ | ✗ |
| 2.0 | ✗ | ✓ | ✗ | ✗ |
| 2.1 | ✗ | ✓ | ✓ | ✗ |
| 3.0 | ✗ | ✗ | ✗ | ✓ |

**Rule**: Writers can only produce current or previous minor versions.

## Compatibility Policy

### Read Compatibility Guarantee

```yaml
readCompatibilityPolicy:
  manifestV2:
    guaranteedUntil: "2031-03-05"  # 5 years from freeze
    minimumDuration: "5 years"

  rules:
    - "Any v2.x manifest readable by latest reader"
    - "Reader MUST support all v2.x features"
    - "Unknown fields in minor versions MUST be preserved"
    - "Missing optional fields use schema defaults"
```

### Write Compatibility Rules

```yaml
writeCompatibilityPolicy:
  rules:
    - "Writers produce manifests matching their version"
    - "Old writers cannot produce new version manifests"
    - "v3.0 release freezes v2.x writer development"
    - "Only security fixes for frozen writers"
```

## Change Classification

### Minor Version (Non-Breaking)

Allowed changes:
- Add new **optional** fields
- Add new enum values (if readers ignore unknown)
- Extend `extensions` object
- Add new event types (if readers skip unknown)
- Relax validation constraints

Example: Adding `acoustics.reliability` field in v2.1

```json
// v2.0 manifest (reader must handle missing field)
{
  "acoustics": {
    "localizationMethod": "augmented_tdoa",
    "estimatedDistance": 5.2
  }
}

// v2.1 manifest (new optional field)
{
  "acoustics": {
    "localizationMethod": "augmented_tdoa",
    "estimatedDistance": 5.2,
    "reliability": 0.95  // NEW in v2.1
  }
}
```

### Major Version (Breaking)

Required for:
- Remove existing fields
- Change field types
- Change field semantics
- Add new **required** fields
- Change cryptographic algorithms
- Change sealHash formula
- Change AAD structure

Example: Changing from SHA-256 to SHA-3 as default requires v3.0

## Forward Compatibility

### Unknown Field Handling

```kotlin
// Reader MUST preserve unknown fields when re-serializing
fun readManifest(json: String): Manifest {
    val parsed = JSON.parse(json)

    val known = Manifest(
        version = parsed["version"],
        evidenceId = parsed["evidenceId"],
        // ... known fields
    )

    // Store unknown fields for round-trip
    known.unknownFields = parsed.keys
        .filter { it !in KNOWN_FIELDS }
        .associateWith { parsed[it] }

    return known
}
```

### Unknown Enum Values

```kotlin
enum class EventType {
    CAPTURE_STARTED,
    CAPTURE_ENDED,
    // ... known types

    UNKNOWN;  // Catch-all for forward compatibility

    companion object {
        fun fromString(value: String): EventType {
            return try {
                valueOf(value)
            } catch (e: IllegalArgumentException) {
                UNKNOWN
            }
        }
    }
}
```

## Migration Procedures

### Minor Version Upgrade

1. Update schema with new optional fields
2. Update readers to handle new fields
3. Update writers to produce new fields
4. Deploy readers first, then writers
5. No data migration required

### Major Version Upgrade

1. Announce deprecation timeline (12+ months)
2. Implement v(N+1) readers
3. Implement v(N+1) writers
4. Dual-write period: produce both versions
5. Migrate existing evidence (if needed)
6. Deprecate v(N) writers
7. Maintain v(N) readers indefinitely

### Deprecation Timeline

```
T+0:   v3.0 announced
T+3m:  v3.0 reader available
T+6m:  v3.0 writer available, dual-write starts
T+12m: v2.x writer deprecated (security fixes only)
T+18m: v2.x writer removed from app
T+∞:   v2.x reader maintained forever
```

## Schema Evolution Examples

### Example 1: Adding Optional Field (v2.0 → v2.1)

```diff
  {
    "type": "object",
    "properties": {
      "acoustics": {
        "type": "object",
        "properties": {
          "localizationMethod": { "type": "string" },
          "estimatedDistance": { "type": "number" },
+         "reliability": {
+           "type": "number",
+           "minimum": 0,
+           "maximum": 1,
+           "description": "Added in v2.1"
+         }
        }
      }
    }
  }
```

### Example 2: Adding New Event Type (v2.0 → v2.1)

```diff
  "EventType": {
    "type": "string",
    "enum": [
      "CAPTURE_STARTED",
      "CAPTURE_ENDED",
+     "QUALITY_CHECKPOINT"  // Added in v2.1
    ]
  }
```

### Example 3: Breaking Change (v2.x → v3.0)

```diff
  // v2.x: sealHash uses SHA-256
  // v3.0: sealHash uses SHA-3-256

  // Manifest version MUST change
- "version": "2.1"
+ "version": "3.0"

  // hashSuiteId in AAD reflects change
- "hashSuiteId": 1  // SHA-256
+ "hashSuiteId": 2  // SHA-3-256
```

## Testing Requirements

### Compatibility Tests

- [ ] v2.0 reader can read v2.0 manifest
- [ ] v2.1 reader can read v2.0 manifest
- [ ] v2.1 reader can read v2.1 manifest
- [ ] v2.0 reader rejects v3.0 manifest gracefully
- [ ] Unknown fields preserved in round-trip
- [ ] Unknown enum values handled gracefully
- [ ] Optional field defaults applied correctly

### CI Integration

```yaml
# .github/workflows/compatibility.yml
compatibility-test:
  matrix:
    reader: [v2.0, v2.1]
    manifest: [v2.0, v2.1]
  steps:
    - run: test-read-compatibility ${{ matrix.reader }} ${{ matrix.manifest }}
```

## Documentation Requirements

### Changelog

Each version MUST document:
- New fields added
- Fields deprecated
- Behavior changes
- Migration notes

### Schema Annotations

```json
{
  "newField": {
    "type": "string",
    "description": "Description here",
    "x-added-in": "2.1",
    "x-deprecated-in": null
  }
}
```
