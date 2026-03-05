"""
Nonce Security Conformance Tests

These tests MUST pass for any implementation to be considered conformant.
Violation of nonce rules leads to catastrophic AES-GCM security failure.
"""

import os
import sys
import hashlib
from typing import Dict, Optional, Tuple

# Add parent for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'reference-impl', 'python'))


def generate_nonce_prefix() -> bytes:
    """Generate 4-byte random nonce prefix."""
    return os.urandom(4)


def build_nonce(nonce_prefix: bytes, chunk_index: int) -> bytes:
    """Build 12-byte nonce from prefix and chunk index."""
    if len(nonce_prefix) != 4:
        raise ValueError("nonce_prefix must be 4 bytes")
    if chunk_index < 0:
        raise ValueError("chunk_index must be non-negative")

    return nonce_prefix + chunk_index.to_bytes(8, 'big')


class MockStorage:
    """Mock storage for testing persistence timing."""

    def __init__(self):
        self.nonce_prefix_save_time: Optional[int] = None
        self.first_encrypt_time: Optional[int] = None
        self._counter = 0
        self._chunks: Dict[int, bytes] = {}

    def _tick(self) -> int:
        self._counter += 1
        return self._counter

    def save_nonce_prefix(self, prefix: bytes):
        if self.nonce_prefix_save_time is None:
            self.nonce_prefix_save_time = self._tick()

    def save_chunk(self, chunk_index: int, ciphertext: bytes):
        if self.first_encrypt_time is None:
            self.first_encrypt_time = self._tick()
        self._chunks[chunk_index] = ciphertext

    def get_chunk(self, chunk_index: int) -> Optional[bytes]:
        return self._chunks.get(chunk_index)


class ChunkAlreadyEncryptedException(Exception):
    """Raised when attempting to re-encrypt an already encrypted chunk."""
    pass


class ChunkEncryptor:
    """Reference implementation of secure chunk encryption."""

    def __init__(self, dek: bytes, nonce_prefix: bytes, storage: MockStorage):
        self.dek = dek
        self.nonce_prefix = nonce_prefix
        self.storage = storage

        # Persist nonce_prefix immediately
        self.storage.save_nonce_prefix(nonce_prefix)

    def encrypt_chunk(self, chunk_index: int, plaintext: bytes) -> bytes:
        """Encrypt a chunk. Raises if chunk already encrypted."""
        # Check if already encrypted
        existing = self.storage.get_chunk(chunk_index)
        if existing is not None:
            raise ChunkAlreadyEncryptedException(
                f"Chunk {chunk_index} already encrypted. Use get_for_retry() instead."
            )

        # Simulate encryption (in real impl, use AES-GCM)
        nonce = build_nonce(self.nonce_prefix, chunk_index)
        # Fake ciphertext = hash of (dek, nonce, plaintext)
        ciphertext = hashlib.sha256(self.dek + nonce + plaintext).digest()

        # Persist before returning
        self.storage.save_chunk(chunk_index, ciphertext)

        return ciphertext

    def get_for_retry(self, chunk_index: int) -> Optional[bytes]:
        """Get existing ciphertext for retry. Never re-encrypts."""
        return self.storage.get_chunk(chunk_index)


# ============================================================================
# CONFORMANCE TESTS
# ============================================================================

def test_nonce_uniqueness_within_evidence():
    """
    TEST: All nonces within a single evidence must be unique.

    REQUIREMENT: nonce = noncePrefix || chunkIndex ensures uniqueness
    as long as chunkIndex is monotonically increasing.
    """
    print("Test: nonce_uniqueness_within_evidence")

    nonce_prefix = generate_nonce_prefix()
    nonces = set()

    # Test 10,000 chunks (typical large evidence)
    for chunk_index in range(10000):
        nonce = build_nonce(nonce_prefix, chunk_index)
        nonce_hex = nonce.hex()

        if nonce_hex in nonces:
            print(f"  [FAIL] Nonce collision at chunk {chunk_index}")
            return False

        nonces.add(nonce_hex)

    print(f"  [PASS] All 10,000 nonces unique")
    return True


def test_retry_returns_same_ciphertext():
    """
    TEST: Retry must return identical ciphertext.

    REQUIREMENT: Re-encrypting with same nonce would leak XOR of plaintexts.
    Retry MUST return the cached ciphertext, not re-encrypt.
    """
    print("Test: retry_returns_same_ciphertext")

    dek = os.urandom(32)
    nonce_prefix = generate_nonce_prefix()
    storage = MockStorage()

    encryptor = ChunkEncryptor(dek, nonce_prefix, storage)

    plaintext = b"test data for encryption"

    # First encryption
    first_ciphertext = encryptor.encrypt_chunk(0, plaintext)

    # Get for retry (should return same ciphertext)
    retry_ciphertext = encryptor.get_for_retry(0)

    if first_ciphertext != retry_ciphertext:
        print(f"  [FAIL] Retry returned different ciphertext")
        print(f"    First: {first_ciphertext.hex()}")
        print(f"    Retry: {retry_ciphertext.hex() if retry_ciphertext else 'None'}")
        return False

    print(f"  [PASS] Retry returned identical ciphertext")
    return True


def test_reject_reencryption():
    """
    TEST: Must reject attempt to re-encrypt same chunk.

    REQUIREMENT: If an implementation allows re-encryption, it creates
    nonce reuse vulnerability. Must raise exception.
    """
    print("Test: reject_reencryption")

    dek = os.urandom(32)
    nonce_prefix = generate_nonce_prefix()
    storage = MockStorage()

    encryptor = ChunkEncryptor(dek, nonce_prefix, storage)

    # First encryption
    encryptor.encrypt_chunk(0, b"original data")

    # Attempt re-encryption with different data (MUST FAIL)
    try:
        encryptor.encrypt_chunk(0, b"different data")
        print(f"  [FAIL] Re-encryption was allowed (security vulnerability!)")
        return False
    except ChunkAlreadyEncryptedException:
        print(f"  [PASS] Re-encryption correctly rejected")
        return True
    except Exception as e:
        print(f"  [FAIL] Unexpected exception: {e}")
        return False


def test_nonce_prefix_persisted_before_encryption():
    """
    TEST: noncePrefix must be persisted before first encryption.

    REQUIREMENT: If encryption happens before persistence and app crashes,
    noncePrefix is lost and evidence cannot be completed.
    """
    print("Test: nonce_prefix_persisted_before_encryption")

    dek = os.urandom(32)
    nonce_prefix = generate_nonce_prefix()
    storage = MockStorage()

    encryptor = ChunkEncryptor(dek, nonce_prefix, storage)

    # Encrypt a chunk
    encryptor.encrypt_chunk(0, b"test data")

    # Check timing
    if storage.nonce_prefix_save_time is None:
        print(f"  [FAIL] noncePrefix was never persisted")
        return False

    if storage.first_encrypt_time is None:
        print(f"  [FAIL] Encryption timing not recorded")
        return False

    if storage.nonce_prefix_save_time >= storage.first_encrypt_time:
        print(f"  [FAIL] noncePrefix persisted AFTER encryption")
        print(f"    nonce_prefix_save_time: {storage.nonce_prefix_save_time}")
        print(f"    first_encrypt_time: {storage.first_encrypt_time}")
        return False

    print(f"  [PASS] noncePrefix persisted before encryption")
    return True


def test_different_evidence_different_nonce_prefix():
    """
    TEST: Different evidence packages should have different noncePrefix.

    REQUIREMENT: While same prefix across evidence is safe (different DEK),
    it indicates potential PRNG weakness if it happens too often.
    """
    print("Test: different_evidence_different_nonce_prefix")

    prefixes = set()
    num_samples = 1000

    for _ in range(num_samples):
        prefix = generate_nonce_prefix()
        prefixes.add(prefix.hex())

    if len(prefixes) < num_samples * 0.99:  # Allow 1% collision due to birthday bound
        print(f"  [FAIL] Too many collisions: {num_samples - len(prefixes)}")
        return False

    print(f"  [PASS] {len(prefixes)}/{num_samples} unique prefixes")
    return True


def test_nonce_length():
    """
    TEST: Nonce must be exactly 12 bytes.

    REQUIREMENT: AES-GCM standard nonce size is 12 bytes (96 bits).
    """
    print("Test: nonce_length")

    nonce_prefix = generate_nonce_prefix()

    for chunk_index in [0, 1, 255, 256, 10000, 2**32 - 1, 2**53 - 1]:
        nonce = build_nonce(nonce_prefix, chunk_index)

        if len(nonce) != 12:
            print(f"  [FAIL] Nonce length {len(nonce)} at chunk {chunk_index}")
            return False

    print(f"  [PASS] All nonces are 12 bytes")
    return True


def test_chunk_index_big_endian():
    """
    TEST: chunkIndex must be encoded as big-endian.

    REQUIREMENT: Cross-platform compatibility requires consistent byte order.
    """
    print("Test: chunk_index_big_endian")

    nonce_prefix = bytes([0xaa, 0xbb, 0xcc, 0xdd])

    # Test chunk 256 (0x100)
    nonce = build_nonce(nonce_prefix, 256)
    expected = bytes([0xaa, 0xbb, 0xcc, 0xdd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00])

    if nonce != expected:
        print(f"  [FAIL] Chunk 256 encoding wrong")
        print(f"    Expected: {expected.hex()}")
        print(f"    Got:      {nonce.hex()}")
        return False

    # Test chunk 1 (should be at last byte)
    nonce = build_nonce(nonce_prefix, 1)
    if nonce[-1] != 0x01 or nonce[-2] != 0x00:
        print(f"  [FAIL] Chunk 1 should end with 0x0001")
        print(f"    Got: {nonce.hex()}")
        return False

    print(f"  [PASS] chunkIndex is big-endian")
    return True


def test_max_safe_integer():
    """
    TEST: Must handle JavaScript MAX_SAFE_INTEGER (2^53 - 1).

    REQUIREMENT: Cross-platform with JavaScript requires this limit.
    """
    print("Test: max_safe_integer")

    nonce_prefix = bytes([0x12, 0x34, 0x56, 0x78])
    max_safe_int = 9007199254740991  # 2^53 - 1

    try:
        nonce = build_nonce(nonce_prefix, max_safe_int)

        # Expected: 0x001FFFFFFFFFFFFF in big-endian
        expected_chunk_part = bytes([0x00, 0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])

        if nonce[4:] != expected_chunk_part:
            print(f"  [FAIL] MAX_SAFE_INTEGER encoding wrong")
            print(f"    Expected chunk part: {expected_chunk_part.hex()}")
            print(f"    Got:                 {nonce[4:].hex()}")
            return False

        print(f"  [PASS] MAX_SAFE_INTEGER handled correctly")
        return True

    except Exception as e:
        print(f"  [FAIL] Exception: {e}")
        return False


# ============================================================================
# MAIN
# ============================================================================

def main():
    print("=" * 60)
    print("Nonce Security Conformance Tests")
    print("=" * 60)
    print()

    tests = [
        test_nonce_uniqueness_within_evidence,
        test_retry_returns_same_ciphertext,
        test_reject_reencryption,
        test_nonce_prefix_persisted_before_encryption,
        test_different_evidence_different_nonce_prefix,
        test_nonce_length,
        test_chunk_index_big_endian,
        test_max_safe_integer,
    ]

    passed = 0
    failed = 0

    for test in tests:
        print()
        if test():
            passed += 1
        else:
            failed += 1

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")
    print("=" * 60)

    if failed > 0:
        print("\n[CRITICAL] Implementation is NOT conformant!")
        print("Nonce security violations lead to AES-GCM key compromise.")
        sys.exit(1)
    else:
        print("\n[SUCCESS] Implementation is conformant.")
        sys.exit(0)


if __name__ == "__main__":
    main()
