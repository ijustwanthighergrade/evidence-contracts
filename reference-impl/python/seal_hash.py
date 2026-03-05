"""
sealHash Computer

Computes the binding hash that ties all evidence components together.
See specs/seal-hash.md for specification.
"""

import hashlib
import struct
import uuid as uuid_module
from typing import Tuple


def compute_seal_hash(
    manifest_hash: bytes,
    media_plaintext_hash: bytes,
    chunk_merkle_root: bytes,
    final_event_hash: bytes,
    session_binding_hash: bytes,
    policy_hash: bytes,
) -> bytes:
    """
    Compute sealHash from all components.

    All inputs must be 32 bytes (SHA-256 hashes).
    Returns 32-byte sealHash.
    """
    # Validate inputs
    for name, value in [
        ("manifest_hash", manifest_hash),
        ("media_plaintext_hash", media_plaintext_hash),
        ("chunk_merkle_root", chunk_merkle_root),
        ("final_event_hash", final_event_hash),
        ("session_binding_hash", session_binding_hash),
        ("policy_hash", policy_hash),
    ]:
        if len(value) != 32:
            raise ValueError(f"{name} must be 32 bytes, got {len(value)}")

    # Concatenate in order (192 bytes total)
    seal_input = (
        manifest_hash
        + media_plaintext_hash
        + chunk_merkle_root
        + final_event_hash
        + session_binding_hash
        + policy_hash
    )

    assert len(seal_input) == 192

    return hashlib.sha256(seal_input).digest()


def compute_session_binding_hash(
    session_id: str,
    server_issued_at_ms: int,
    app_signature_digest: bytes,
    device_key_id: str,
) -> bytes:
    """
    Compute sessionBindingHash.

    Args:
        session_id: UUID string
        server_issued_at_ms: Unix epoch milliseconds
        app_signature_digest: 32-byte SHA-256 of app signing cert
        device_key_id: UTF-8 string identifier

    Returns:
        32-byte sessionBindingHash
    """
    if len(app_signature_digest) != 32:
        raise ValueError("app_signature_digest must be 32 bytes")

    # Convert UUID to network bytes
    uuid_bytes = uuid_module.UUID(session_id).bytes

    # Encode device_key_id as length-prefixed UTF-8
    device_key_id_bytes = device_key_id.encode("utf-8")
    if len(device_key_id_bytes) > 65535:
        raise ValueError("device_key_id too long")

    # Build buffer
    # 16 (UUID) + 8 (timestamp) + 32 (digest) + 2 (length) + deviceKeyId
    buffer = bytearray()
    buffer.extend(uuid_bytes)
    buffer.extend(struct.pack(">Q", server_issued_at_ms))
    buffer.extend(app_signature_digest)
    buffer.extend(struct.pack(">H", len(device_key_id_bytes)))
    buffer.extend(device_key_id_bytes)

    return hashlib.sha256(bytes(buffer)).digest()


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


def verify_seal_hash(
    expected_hex: str,
    manifest_hash_hex: str,
    media_plaintext_hash_hex: str,
    chunk_merkle_root_hex: str,
    final_event_hash_hex: str,
    session_binding_hash_hex: str,
    policy_hash_hex: str,
) -> Tuple[bool, str]:
    """Verify a sealHash test vector."""
    try:
        computed = compute_seal_hash(
            hex_to_bytes(manifest_hash_hex),
            hex_to_bytes(media_plaintext_hash_hex),
            hex_to_bytes(chunk_merkle_root_hex),
            hex_to_bytes(final_event_hash_hex),
            hex_to_bytes(session_binding_hash_hex),
            hex_to_bytes(policy_hash_hex),
        )
        computed_hex = bytes_to_hex(computed)

        if computed_hex == expected_hex.lower():
            return True, computed_hex
        else:
            return False, f"expected {expected_hex}, got {computed_hex}"
    except Exception as e:
        return False, str(e)


if __name__ == "__main__":
    print("=== sealHash Test Vectors ===\n")

    # Test vector seal-002: All zeros
    print("Test seal-002 (all zeros):")
    result, msg = verify_seal_hash(
        expected_hex="374708fff7719dd5979ec875d56cd2286f6d3cf7ec317a3b25632aab28ec37bb",
        manifest_hash_hex="0" * 64,
        media_plaintext_hash_hex="0" * 64,
        chunk_merkle_root_hex="0" * 64,
        final_event_hash_hex="0" * 64,
        session_binding_hash_hex="0" * 64,
        policy_hash_hex="0" * 64,
    )
    if result:
        print("  ✓ PASSED")
    else:
        print(f"  ✗ FAILED: {msg}")
        exit(1)

    # Test concatenation order
    print("\nTest seal-order (order sensitivity):")
    # Same hashes but different order should produce different result
    seal1 = compute_seal_hash(
        hex_to_bytes("aa" * 32),
        hex_to_bytes("bb" * 32),
        hex_to_bytes("cc" * 32),
        hex_to_bytes("dd" * 32),
        hex_to_bytes("ee" * 32),
        hex_to_bytes("ff" * 32),
    )
    seal2 = compute_seal_hash(
        hex_to_bytes("bb" * 32),  # swapped
        hex_to_bytes("aa" * 32),  # swapped
        hex_to_bytes("cc" * 32),
        hex_to_bytes("dd" * 32),
        hex_to_bytes("ee" * 32),
        hex_to_bytes("ff" * 32),
    )
    if seal1 != seal2:
        print("  ✓ PASSED (different order = different hash)")
    else:
        print("  ✗ FAILED (order should matter)")
        exit(1)

    # Test input length validation
    print("\nTest seal-length (input validation):")
    try:
        compute_seal_hash(
            hex_to_bytes("aa" * 31),  # Wrong length
            hex_to_bytes("bb" * 32),
            hex_to_bytes("cc" * 32),
            hex_to_bytes("dd" * 32),
            hex_to_bytes("ee" * 32),
            hex_to_bytes("ff" * 32),
        )
        print("  ✗ FAILED (should reject wrong length)")
        exit(1)
    except ValueError:
        print("  ✓ PASSED (rejected invalid input)")

    print("\n=== All sealHash tests passed ===")
