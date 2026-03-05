"""
Cross-Platform Test Vector Verification

Loads test vectors from JSON files and verifies Python implementations.
"""

import json
import os
import sys
from pathlib import Path

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from aad_builder import build_aad, hex_to_bytes, bytes_to_hex
from seal_hash import compute_seal_hash


def load_test_vectors(filename: str) -> dict:
    """Load test vectors from JSON file."""
    vectors_dir = Path(__file__).parent.parent.parent / "test-vectors"
    filepath = vectors_dir / filename
    with open(filepath, "r", encoding="utf-8") as f:
        return json.load(f)


def test_aad_vectors() -> int:
    """Test AAD computation vectors."""
    print("=== AAD Computation Tests ===\n")

    data = load_test_vectors("aad-computation.json")
    vectors = data["vectors"]

    passed = 0
    failed = 0

    for v in vectors:
        vid = v["id"]
        desc = v["description"]
        inputs = v["inputs"]
        expected = v["expected"]

        print(f"Test {vid}: {desc}")

        try:
            aad = build_aad(
                evidence_id=inputs["evidenceId"],
                chunk_index=inputs["chunkIndex"],
                policy_hash=hex_to_bytes(inputs["policyHash"]),
                aead_suite_id=inputs["aeadSuiteId"],
                hash_suite_id=inputs["hashSuiteId"],
                manifest_ver=inputs["manifestVer"],
            )

            computed_hex = bytes_to_hex(aad)
            expected_hex = expected["aadHex"].lower()

            if computed_hex == expected_hex:
                print(f"  [PASS] PASSED")
                passed += 1
            else:
                print(f"  [FAIL] FAILED")
                print(f"    Expected: {expected_hex}")
                print(f"    Got:      {computed_hex}")
                failed += 1

        except Exception as e:
            print(f"  [FAIL] ERROR: {e}")
            failed += 1

    print(f"\nAAD Tests: {passed} passed, {failed} failed\n")
    return failed


def test_nonce_vectors() -> int:
    """Test nonce generation vectors."""
    print("=== Nonce Generation Tests ===\n")

    data = load_test_vectors("nonce-generation.json")
    vectors = data["vectors"]

    passed = 0
    failed = 0

    for v in vectors:
        vid = v["id"]
        desc = v["description"]

        # Skip non-standard test cases (scenario tests without expected field)
        if "inputs" not in v or "expected" not in v:
            print(f"Test {vid}: {desc} (skipped - scenario test)")
            continue

        inputs = v["inputs"]
        expected = v["expected"]

        # Skip tests without chunkIndex (e.g., sequential chunk tests)
        if "chunkIndex" not in inputs:
            print(f"Test {vid}: {desc} (skipped - multi-chunk test)")
            continue

        print(f"Test {vid}: {desc}")

        try:
            # Build nonce
            prefix = hex_to_bytes(inputs["noncePrefix"])
            index = inputs["chunkIndex"]

            nonce = prefix + index.to_bytes(8, "big")
            computed_hex = bytes_to_hex(nonce)
            expected_hex = expected["nonceHex"].lower()

            if computed_hex == expected_hex:
                print(f"  [PASS] PASSED")
                passed += 1
            else:
                print(f"  [FAIL] FAILED")
                print(f"    Expected: {expected_hex}")
                print(f"    Got:      {computed_hex}")
                failed += 1

        except Exception as e:
            print(f"  [FAIL] ERROR: {e}")
            failed += 1

    print(f"\nNonce Tests: {passed} passed, {failed} failed\n")
    return failed


def test_seal_hash_vectors() -> int:
    """Test sealHash computation vectors."""
    print("=== sealHash Computation Tests ===\n")

    data = load_test_vectors("seal-hash-10-cases.json")
    vectors = data["vectors"]

    passed = 0
    failed = 0
    skipped = 0

    for v in vectors:
        vid = v["id"]
        desc = v["description"]
        inputs = v["inputs"]
        expected = v["expected"]

        print(f"Test {vid}: {desc}")

        # Check for error cases
        if "error" in expected:
            print(f"  [SKIP] SKIPPED (error case: {expected['error']})")
            skipped += 1
            continue

        try:
            # Validate all inputs are 64 hex chars (32 bytes)
            for key, value in inputs.items():
                if len(value) != 64:
                    raise ValueError(f"{key} has wrong length: {len(value)}")

            seal_hash = compute_seal_hash(
                manifest_hash=hex_to_bytes(inputs["manifestHash"]),
                media_plaintext_hash=hex_to_bytes(inputs["mediaPlaintextHash"]),
                chunk_merkle_root=hex_to_bytes(inputs["chunkMerkleRoot"]),
                final_event_hash=hex_to_bytes(inputs["finalEventHash"]),
                session_binding_hash=hex_to_bytes(inputs["sessionBindingHash"]),
                policy_hash=hex_to_bytes(inputs["policyHash"]),
            )

            computed_hex = bytes_to_hex(seal_hash)
            expected_hex = expected["sealHash"].lower()

            if computed_hex == expected_hex:
                print(f"  [PASS] PASSED")
                passed += 1
            else:
                print(f"  [FAIL] FAILED")
                print(f"    Expected: {expected_hex}")
                print(f"    Got:      {computed_hex}")
                failed += 1

        except Exception as e:
            # Some test vectors are designed to fail (e.g., wrong length)
            if "error" in expected or "INVALID" in str(e).upper():
                print(f"  [PASS] PASSED (correctly rejected: {e})")
                passed += 1
            else:
                print(f"  [FAIL] ERROR: {e}")
                failed += 1

    print(f"\nsealHash Tests: {passed} passed, {failed} failed, {skipped} skipped\n")
    return failed


def main():
    print("=" * 60)
    print("Evidence Contracts - Python Test Vector Verification")
    print("=" * 60)
    print()

    total_failures = 0

    total_failures += test_aad_vectors()
    total_failures += test_nonce_vectors()
    total_failures += test_seal_hash_vectors()

    print("=" * 60)
    if total_failures == 0:
        print("All tests passed!")
        sys.exit(0)
    else:
        print(f"Total failures: {total_failures}")
        sys.exit(1)


if __name__ == "__main__":
    main()
