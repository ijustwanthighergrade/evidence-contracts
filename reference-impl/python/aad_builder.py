"""
AAD (Additional Authenticated Data) Builder

Constructs the 60-byte AAD structure for AES-GCM encryption.
See specs/aad-format.md for specification.
"""

import struct
import uuid as uuid_module
from dataclasses import dataclass
from typing import Optional

AAD_SIZE = 60

# AEAD Suite IDs
AEAD_AES_256_GCM = 0x01
AEAD_AES_256_GCM_SIV = 0x02

# Hash Suite IDs
HASH_SHA_256 = 0x01
HASH_SHA3_256 = 0x02


def build_aad(
    evidence_id: str,
    chunk_index: int,
    policy_hash: bytes,
    aead_suite_id: int = AEAD_AES_256_GCM,
    hash_suite_id: int = HASH_SHA_256,
    manifest_ver: int = 2,
) -> bytes:
    """
    Build AAD for a chunk.

    Args:
        evidence_id: UUID string (e.g., "550e8400-e29b-41d4-a716-446655440000")
        chunk_index: 0-based chunk index
        policy_hash: 32-byte SHA-256 of policy document
        aead_suite_id: AEAD algorithm (1=AES-256-GCM, 2=AES-256-GCM-SIV)
        hash_suite_id: Hash algorithm (1=SHA-256, 2=SHA-3-256)
        manifest_ver: Manifest version (e.g., 2)

    Returns:
        60-byte AAD
    """
    if len(policy_hash) != 32:
        raise ValueError("policy_hash must be 32 bytes")
    if chunk_index < 0:
        raise ValueError("chunk_index must be non-negative")
    if not (0 <= manifest_ver <= 65535):
        raise ValueError("manifest_ver must fit in uint16")

    # Build AAD
    aad = bytearray(AAD_SIZE)

    # Offset 0: aeadSuiteId (1 byte)
    aad[0] = aead_suite_id

    # Offset 1: hashSuiteId (1 byte)
    aad[1] = hash_suite_id

    # Offset 2-17: evidenceId (16 bytes, network order)
    uuid_bytes = uuid_to_network_bytes(evidence_id)
    aad[2:18] = uuid_bytes

    # Offset 18-25: chunkIndex (8 bytes, big-endian)
    struct.pack_into(">Q", aad, 18, chunk_index)

    # Offset 26-27: manifestVer (2 bytes, big-endian)
    struct.pack_into(">H", aad, 26, manifest_ver)

    # Offset 28-59: policyHash (32 bytes)
    aad[28:60] = policy_hash

    return bytes(aad)


def uuid_to_network_bytes(uuid_str: str) -> bytes:
    """
    Convert UUID string to network byte order (big-endian).

    WARNING: Do NOT use uuid.UUID().bytes which may use different byte order
    on some platforms. This function ensures RFC4122 network byte order.
    """
    # Parse UUID and get bytes in network order
    parsed = uuid_module.UUID(uuid_str)
    return parsed.bytes  # Python's uuid.bytes is already big-endian


def uuid_from_network_bytes(data: bytes) -> str:
    """Convert network byte order to UUID string."""
    if len(data) != 16:
        raise ValueError("UUID bytes must be 16 bytes")
    return str(uuid_module.UUID(bytes=data))


@dataclass
class AadComponents:
    """Parsed AAD components."""

    aead_suite_id: int
    hash_suite_id: int
    evidence_id: str
    chunk_index: int
    manifest_ver: int
    policy_hash: bytes


def parse_aad(aad: bytes) -> AadComponents:
    """Parse AAD back to components (for debugging/verification)."""
    if len(aad) != AAD_SIZE:
        raise ValueError(f"AAD must be {AAD_SIZE} bytes")

    aead_suite_id = aad[0]
    hash_suite_id = aad[1]
    evidence_id = uuid_from_network_bytes(aad[2:18])
    chunk_index = struct.unpack_from(">Q", aad, 18)[0]
    manifest_ver = struct.unpack_from(">H", aad, 26)[0]
    policy_hash = bytes(aad[28:60])

    return AadComponents(
        aead_suite_id=aead_suite_id,
        hash_suite_id=hash_suite_id,
        evidence_id=evidence_id,
        chunk_index=chunk_index,
        manifest_ver=manifest_ver,
        policy_hash=policy_hash,
    )


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


# Test vectors validation
def validate_test_vector(
    expected_hex: str,
    aead_suite_id: int,
    hash_suite_id: int,
    evidence_id: str,
    chunk_index: int,
    manifest_ver: int,
    policy_hash_hex: str,
) -> bool:
    """Validate a single test vector."""
    policy_hash = hex_to_bytes(policy_hash_hex)
    aad = build_aad(
        evidence_id=evidence_id,
        chunk_index=chunk_index,
        policy_hash=policy_hash,
        aead_suite_id=aead_suite_id,
        hash_suite_id=hash_suite_id,
        manifest_ver=manifest_ver,
    )
    computed_hex = bytes_to_hex(aad)
    return computed_hex == expected_hex.lower()


if __name__ == "__main__":
    # Quick self-test with test vector aad-001
    expected = "0101550e8400e29b41d4a716446655440000000000000000000002d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"

    result = validate_test_vector(
        expected_hex=expected,
        aead_suite_id=1,
        hash_suite_id=1,
        evidence_id="550e8400-e29b-41d4-a716-446655440000",
        chunk_index=0,
        manifest_ver=2,
        policy_hash_hex="d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592",
    )

    if result:
        print("✓ Test vector aad-001 passed")
    else:
        print("✗ Test vector aad-001 FAILED")
        exit(1)
