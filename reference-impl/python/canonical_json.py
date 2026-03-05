"""
RFC 8785 JSON Canonicalization Scheme (JCS) Implementation

This is a reference implementation for evidence-contracts.
For production, use established libraries.
"""

import hashlib
import json
import re
from typing import Any, Union


def canonicalize(obj: Any) -> str:
    """
    Convert a Python object to canonical JSON string per RFC 8785.

    Args:
        obj: Any JSON-serializable Python object

    Returns:
        Canonical JSON string (UTF-8 compatible)
    """
    return _serialize(obj)


def _serialize(value: Any) -> str:
    """Recursively serialize value to canonical JSON."""
    if value is None:
        return "null"
    elif isinstance(value, bool):
        return "true" if value else "false"
    elif isinstance(value, int):
        return str(value)
    elif isinstance(value, float):
        return _serialize_number(value)
    elif isinstance(value, str):
        return _serialize_string(value)
    elif isinstance(value, list):
        return "[" + ",".join(_serialize(item) for item in value) + "]"
    elif isinstance(value, dict):
        # Sort keys by UTF-16 code unit values
        sorted_keys = sorted(value.keys(), key=_utf16_sort_key)
        pairs = [_serialize_string(k) + ":" + _serialize(value[k]) for k in sorted_keys]
        return "{" + ",".join(pairs) + "}"
    else:
        raise TypeError(f"Cannot serialize type: {type(value)}")


def _utf16_sort_key(s: str) -> list:
    """
    Return sort key based on UTF-16 code units.

    RFC 8785 requires sorting by UTF-16 code unit values.
    """
    return [ord(c) for c in s]


def _serialize_number(num: float) -> str:
    """
    Serialize number per RFC 8785 rules.

    - No trailing zeros
    - No positive exponent sign
    - Shortest representation
    """
    if num == 0:
        return "0"
    if num == int(num):
        return str(int(num))

    # Use repr for full precision, then clean up
    s = repr(num)

    # Handle scientific notation - expand if small exponent
    if 'e' in s or 'E' in s:
        # Parse the number and format without scientific notation if reasonable
        formatted = f"{num:.15g}"
        if 'e' not in formatted.lower():
            s = formatted
        else:
            # Keep scientific notation but normalize
            s = formatted.lower()

    # Remove trailing zeros after decimal point
    if '.' in s:
        s = s.rstrip('0').rstrip('.')

    return s


def _serialize_string(s: str) -> str:
    """
    Serialize string per RFC 8785 rules.

    - Control characters (U+0000-U+001F) use \\uXXXX
    - Quote and backslash escaped
    - All other Unicode literal
    """
    result = ['"']

    for char in s:
        code = ord(char)

        if char == '"':
            result.append('\\"')
        elif char == '\\':
            result.append('\\\\')
        elif code <= 0x1F:
            # Control characters
            if char == '\n':
                result.append('\\n')
            elif char == '\r':
                result.append('\\r')
            elif char == '\t':
                result.append('\\t')
            elif char == '\b':
                result.append('\\b')
            elif char == '\f':
                result.append('\\f')
            else:
                result.append(f'\\u{code:04x}')
        else:
            result.append(char)

    result.append('"')
    return ''.join(result)


def canonical_hash(obj: Any) -> bytes:
    """
    Compute SHA-256 hash of canonical JSON.

    Args:
        obj: JSON-serializable object

    Returns:
        32-byte SHA-256 hash
    """
    canonical = canonicalize(obj)
    return hashlib.sha256(canonical.encode('utf-8')).digest()


def canonical_hash_hex(obj: Any) -> str:
    """
    Compute SHA-256 hash of canonical JSON as hex string.
    """
    return canonical_hash(obj).hex()


# ============================================================================
# TEST VECTORS
# ============================================================================

def run_tests():
    """Run RFC 8785 compliance tests."""
    print("=== Canonical JSON (RFC 8785) Tests ===\n")

    passed = 0
    failed = 0

    tests = [
        # (name, input, expected_canonical)
        ("Simple sorted keys",
         {"z": 1, "a": 2, "m": 3},
         '{"a":2,"m":3,"z":1}'),

        ("Nested objects",
         {"outer": {"z": 1, "a": 2}, "name": "test"},
         '{"name":"test","outer":{"a":2,"z":1}}'),

        ("Number - no trailing zeros",
         {"a": 1.0, "b": 1.5, "c": 1.50},
         '{"a":1,"b":1.5,"c":1.5}'),

        ("Zero variations",
         {"zero": 0.0, "negZero": -0.0},
         '{"negZero":0,"zero":0}'),

        ("Boolean and null",
         {"true": True, "false": False, "null": None},
         '{"false":false,"null":null,"true":true}'),

        ("String escaping",
         {"quote": 'a"b', "backslash": "a\\b"},
         '{"backslash":"a\\\\b","quote":"a\\"b"}'),

        ("Control characters",
         {"tab": "a\tb", "newline": "a\nb"},
         '{"newline":"a\\nb","tab":"a\\tb"}'),

        ("Unicode - not escaped",
         {"chinese": "中文", "emoji": "🎉"},
         '{"chinese":"中文","emoji":"🎉"}'),

        ("UTF-16 key sorting",
         {"ä": 1, "z": 2, "a": 3},
         '{"a":3,"z":2,"ä":1}'),

        ("Empty objects and arrays",
         {"obj": {}, "arr": []},
         '{"arr":[],"obj":{}}'),

        ("Array with mixed types",
         {"mixed": [1, "two", True, None]},
         '{"mixed":[1,"two",true,null]}'),

        ("Nested array objects",
         {"arr": [{"b": 2, "a": 1}]},
         '{"arr":[{"a":1,"b":2}]}'),

        ("Integer limits",
         {"max": 9007199254740991, "min": -9007199254740991},
         '{"max":9007199254740991,"min":-9007199254740991}'),
    ]

    for name, input_obj, expected in tests:
        result = canonicalize(input_obj)

        if result == expected:
            print(f"[PASS] {name}")
            passed += 1
        else:
            print(f"[FAIL] {name}")
            print(f"  Expected: {expected}")
            print(f"  Got:      {result}")
            failed += 1

    print(f"\nResults: {passed} passed, {failed} failed")

    # Compute hashes for test vectors
    print("\n=== Computed Hashes for Test Vectors ===\n")

    test_vectors = [
        ("jcs-001", {"z": 1, "a": 2, "m": 3}),
        ("jcs-002", {"outer": {"z": 1, "a": 2}, "name": "test"}),
        ("jcs-011", {
            "version": "2.0",
            "evidenceId": "550e8400-e29b-41d4-a716-446655440000",
            "device": {"model": "Pixel 7a", "osVersion": "14"},
            "encryption": {"aeadSuiteId": 1, "chunkSize": 8388608}
        }),
    ]

    for name, obj in test_vectors:
        canonical = canonicalize(obj)
        hash_hex = canonical_hash_hex(obj)
        print(f"{name}:")
        print(f"  Canonical: {canonical}")
        print(f"  SHA-256:   {hash_hex}")
        print()

    return failed == 0


if __name__ == "__main__":
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
