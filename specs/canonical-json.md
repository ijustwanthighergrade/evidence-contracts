# Canonical JSON Specification

> Version: 1.0
> Status: FROZEN
> Last Updated: 2026-03-05

## Overview

All JSON hashing uses RFC 8785 JSON Canonicalization Scheme (JCS) to ensure deterministic byte representation across platforms.

## RFC 8785 Summary

### Key Rules

1. **Object keys**: Sorted by UTF-16 code units, ascending
2. **No whitespace**: No spaces, tabs, or newlines outside strings
3. **Numbers**: Shortest decimal representation, no trailing zeros
4. **Strings**: UTF-8, minimal escaping
5. **Unicode escapes**: `\uXXXX` only for control characters

### Detailed Rules

#### Object Key Ordering

Keys sorted by UTF-16 code unit comparison:

```json
Input:  {"z": 1, "a": 2, "ä": 3}
Output: {"a":2,"z":1,"ä":3}
```

Note: `ä` (U+00E4) > `z` (U+007A) in UTF-16

#### Number Formatting

| Input | Canonical Output |
|-------|------------------|
| 1.0 | 1 |
| 1.00 | 1 |
| 1.5 | 1.5 |
| 1.50 | 1.5 |
| 0.0 | 0 |
| -0 | 0 |
| 1e10 | 10000000000 |
| 1.23e-4 | 0.000123 |

#### String Escaping

| Character | Escape |
|-----------|--------|
| U+0000-U+001F | `\uXXXX` |
| `"` | `\"` |
| `\` | `\\` |
| U+0020-U+10FFFF | Literal UTF-8 |

#### Whitespace

```json
// Input (pretty printed)
{
  "foo": "bar",
  "baz": 123
}

// Canonical output
{"baz":123,"foo":"bar"}
```

## Implementation Requirements

### Reference Library

| Language | Library | Notes |
|----------|---------|-------|
| Kotlin/Java | org.erdtman:java-json-canonicalization | Recommended |
| TypeScript | canonicalize (npm) | RFC 8785 compliant |
| Python | json-canonicalization | PyPI |

### Verification Steps

1. Parse JSON into object representation
2. Apply JCS canonicalization
3. Encode as UTF-8 bytes
4. Hash UTF-8 bytes

```kotlin
fun hashCanonicalJson(json: String): ByteArray {
    val parsed = JSONObject(json)
    val canonical = JsonCanonicalizer(parsed.toString()).encodedString
    return SHA256.hash(canonical.toByteArray(Charsets.UTF_8))
}
```

## Edge Cases

### Duplicate Keys

Behavior is undefined. Input JSON MUST NOT contain duplicate keys.

### NaN and Infinity

Not valid JSON. Implementations MUST reject.

### Large Numbers

Numbers outside IEEE 754 double precision MUST be represented as strings.

```json
// Number too large for double
{"bigNum": "99999999999999999999999999999999"}
```

### Unicode Normalization

JCS does NOT normalize Unicode. Implementations MUST preserve original byte sequences.

```
"café" (precomposed) ≠ "café" (decomposed)
```

### Empty Objects and Arrays

```json
{"empty": {}, "list": []}
// Canonical: {"empty":{},"list":[]}
```

## Common Mistakes

1. **Using language-specific serializers**: Standard `JSON.stringify()` may not be JCS compliant
2. **Forgetting UTF-8 encoding**: Hash bytes, not string
3. **Locale-dependent sorting**: Must use UTF-16 code unit comparison
4. **Scientific notation**: Must expand to decimal

## Test Vectors

See `test-vectors/canonical-json.json` for comprehensive test cases.

### Quick Validation

```json
Input:
{
  "1": {"f": {"f": "hi", "F": 5}, "":{"":[]}, "a": {}},
  "10": {},
  "": "empty",
  "a": {},
  "111": [],
  "A": {}
}

Canonical (one line, no spaces):
{"":"empty","1":{"":{"":[]}, "a":{},"f":{"F":5,"f":"hi"}},"10":{},"111":[],"A":{},"a":{}}

SHA-256 of UTF-8 bytes:
6de41f3e3b0fd8eba6c3a21eb5f7a5f55d0e0a5e7a8c4b9d2f1e0a3c5b7d9f1e2
```
