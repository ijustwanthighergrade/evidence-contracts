# UUID Byte Order Specification

> Version: 1.0
> Status: FROZEN
> Last Updated: 2026-03-05

## Overview

UUIDs in the evidence platform MUST use RFC4122 network byte order (big-endian). This document clarifies the byte ordering to prevent cross-platform issues.

## The Problem

Different platforms serialize UUIDs differently:

| Platform | Method | Byte Order |
|----------|--------|------------|
| RFC4122 | Standard | Big-endian (network order) |
| .NET Guid | `ToByteArray()` | Mixed-endian (BROKEN) |
| Java UUID | `getMostSignificantBits()` | Big-endian |
| Python uuid | `.bytes` | Big-endian |
| JavaScript | Manual | Implementation-dependent |

### .NET Guid Danger

```csharp
// UUID string: "12345678-1234-5678-1234-567812345678"
// Expected bytes (RFC4122): 12 34 56 78 12 34 56 78 12 34 56 78 12 34 56 78

Guid guid = Guid.Parse("12345678-1234-5678-1234-567812345678");
byte[] bytes = guid.ToByteArray();
// ACTUAL bytes: 78 56 34 12 34 12 78 56 12 34 56 78 12 34 56 78
//                ^^^^^^^^^^^^ ^^^^^ ^^^^^
//                reversed     rev   rev   (last 8 bytes OK)
```

**This causes AAD mismatch and decryption failure.**

## RFC4122 Network Byte Order

### Canonical Format

```
UUID string:  XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
              |______| |__| |__| |__| |__________|
              time_low mid  hi   seq  node
              (4B)     (2B) (2B) (2B) (6B)

Bytes:        [0..3]   [4..5] [6..7] [8..9] [10..15]
```

### Byte Layout

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0-3 | 4 | time_low | Big-endian |
| 4-5 | 2 | time_mid | Big-endian |
| 6-7 | 2 | time_hi_and_version | Big-endian |
| 8-9 | 2 | clock_seq | Big-endian |
| 10-15 | 6 | node | Network order |

### Example

```
UUID string: "550e8400-e29b-41d4-a716-446655440000"

Correct bytes (hex):
55 0e 84 00  e2 9b  41 d4  a7 16  44 66 55 44 00 00
|__________|  |__|  |__|  |__|  |________________|
time_low     mid   hi    seq   node
```

## Implementation Guidelines

### Kotlin/Java (Correct)

```kotlin
fun uuidToNetworkBytes(uuid: UUID): ByteArray {
    val buffer = ByteBuffer.allocate(16)
    buffer.order(ByteOrder.BIG_ENDIAN)
    buffer.putLong(uuid.mostSignificantBits)
    buffer.putLong(uuid.leastSignificantBits)
    return buffer.array()
}

fun uuidFromNetworkBytes(bytes: ByteArray): UUID {
    require(bytes.size == 16)
    val buffer = ByteBuffer.wrap(bytes)
    buffer.order(ByteOrder.BIG_ENDIAN)
    return UUID(buffer.getLong(), buffer.getLong())
}
```

### TypeScript (Correct)

```typescript
function uuidToNetworkBytes(uuid: string): Uint8Array {
    const hex = uuid.replace(/-/g, '');
    if (hex.length !== 32) throw new Error('Invalid UUID');

    const bytes = new Uint8Array(16);
    for (let i = 0; i < 16; i++) {
        bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
    }
    return bytes;
}
```

### Python (Correct)

```python
import uuid

def uuid_to_network_bytes(uuid_str: str) -> bytes:
    parsed = uuid.UUID(uuid_str)
    return parsed.bytes  # Already big-endian in Python

def uuid_from_network_bytes(data: bytes) -> str:
    return str(uuid.UUID(bytes=data))
```

### C# (.NET) - MUST FIX

```csharp
// WRONG - Do NOT use this:
// byte[] bytes = guid.ToByteArray();

// CORRECT:
public static byte[] GuidToNetworkBytes(Guid guid)
{
    string hex = guid.ToString("N"); // No dashes
    byte[] bytes = new byte[16];
    for (int i = 0; i < 16; i++)
    {
        bytes[i] = Convert.ToByte(hex.Substring(i * 2, 2), 16);
    }
    return bytes;
}

// Or using Span<T> for performance:
public static byte[] GuidToNetworkBytes(Guid guid)
{
    Span<byte> bytes = stackalloc byte[16];
    guid.TryWriteBytes(bytes); // Little-endian

    // Fix byte order for first 3 fields
    // time_low (bytes 0-3): reverse
    (bytes[0], bytes[1], bytes[2], bytes[3]) =
        (bytes[3], bytes[2], bytes[1], bytes[0]);
    // time_mid (bytes 4-5): reverse
    (bytes[4], bytes[5]) = (bytes[5], bytes[4]);
    // time_hi (bytes 6-7): reverse
    (bytes[6], bytes[7]) = (bytes[7], bytes[6]);
    // bytes 8-15 are already correct

    return bytes.ToArray();
}
```

## Verification

### Test Vector

```yaml
uuid_string: "550e8400-e29b-41d4-a716-446655440000"

expected_bytes_hex: "550e8400e29b41d4a716446655440000"

expected_bytes_array:
  - 0x55, 0x0e, 0x84, 0x00  # time_low
  - 0xe2, 0x9b              # time_mid
  - 0x41, 0xd4              # time_hi_and_version
  - 0xa7, 0x16              # clock_seq
  - 0x44, 0x66, 0x55, 0x44, 0x00, 0x00  # node
```

### Conformance Test

All implementations MUST pass this test:

```python
def test_uuid_byte_order():
    uuid_str = "550e8400-e29b-41d4-a716-446655440000"
    expected = bytes.fromhex("550e8400e29b41d4a716446655440000")

    actual = uuid_to_network_bytes(uuid_str)

    assert actual == expected, f"UUID byte order mismatch: {actual.hex()}"
```

## Security Impact

Incorrect UUID byte order causes:

1. **AAD mismatch** → GCM authentication failure → decryption rejected
2. **sealHash mismatch** → signature verification failure
3. **Evidence lookup failure** → wrong database records

These are all **silent failures** that may not be detected until verification.

## Audit Checklist

- [ ] All UUID serialization uses network byte order
- [ ] No use of .NET `Guid.ToByteArray()` without fix
- [ ] Cross-platform test vectors pass
- [ ] CI includes UUID byte order conformance test
