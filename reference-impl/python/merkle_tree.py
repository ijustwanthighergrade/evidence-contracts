"""
Merkle Tree Implementation for Evidence Contracts

Computes chunk Merkle roots and generates inclusion proofs.
"""

import hashlib
from dataclasses import dataclass
from typing import List, Optional, Tuple


@dataclass
class ProofElement:
    """Single element in a Merkle proof."""
    position: str  # "left" or "right"
    hash: bytes

    def to_dict(self) -> dict:
        return {
            "position": self.position,
            "hash": self.hash.hex()
        }


@dataclass
class MerkleProof:
    """Complete inclusion proof for a leaf."""
    leaf_index: int
    leaf_hash: bytes
    proof: List[ProofElement]
    root: bytes

    def to_dict(self) -> dict:
        return {
            "leafIndex": self.leaf_index,
            "leafHash": self.leaf_hash.hex(),
            "proof": [p.to_dict() for p in self.proof],
            "root": self.root.hex()
        }


def sha256(data: bytes) -> bytes:
    """Compute SHA-256 hash."""
    return hashlib.sha256(data).digest()


def compute_merkle_root(leaves: List[bytes]) -> bytes:
    """
    Compute Merkle root from leaf hashes.

    Args:
        leaves: List of 32-byte leaf hashes

    Returns:
        32-byte Merkle root

    Algorithm:
        - If odd number of nodes, duplicate the last one
        - Hash pairs: SHA-256(left || right)
        - Repeat until single root
    """
    if not leaves:
        raise ValueError("Cannot compute Merkle root of empty list")

    if len(leaves) == 1:
        return leaves[0]

    # Work with a copy
    current_level = list(leaves)

    while len(current_level) > 1:
        next_level = []

        # Pad with duplicate if odd
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])

        # Hash pairs
        for i in range(0, len(current_level), 2):
            left = current_level[i]
            right = current_level[i + 1]
            parent = sha256(left + right)
            next_level.append(parent)

        current_level = next_level

    return current_level[0]


def compute_merkle_proof(leaves: List[bytes], leaf_index: int) -> MerkleProof:
    """
    Generate inclusion proof for a specific leaf.

    Args:
        leaves: List of all leaf hashes
        leaf_index: Index of the leaf to prove

    Returns:
        MerkleProof with path from leaf to root
    """
    if not leaves:
        raise ValueError("Cannot compute proof for empty list")

    if leaf_index < 0 or leaf_index >= len(leaves):
        raise ValueError(f"Invalid leaf index: {leaf_index}")

    if len(leaves) == 1:
        return MerkleProof(
            leaf_index=0,
            leaf_hash=leaves[0],
            proof=[],
            root=leaves[0]
        )

    proof_elements = []
    current_index = leaf_index
    current_level = list(leaves)

    while len(current_level) > 1:
        # Pad if odd
        if len(current_level) % 2 == 1:
            current_level.append(current_level[-1])

        # Find sibling
        if current_index % 2 == 0:
            # Left node, sibling is on right
            sibling_index = current_index + 1
            position = "right"
        else:
            # Right node, sibling is on left
            sibling_index = current_index - 1
            position = "left"

        sibling_hash = current_level[sibling_index]
        proof_elements.append(ProofElement(position=position, hash=sibling_hash))

        # Build next level
        next_level = []
        for i in range(0, len(current_level), 2):
            parent = sha256(current_level[i] + current_level[i + 1])
            next_level.append(parent)

        current_level = next_level
        current_index = current_index // 2

    root = current_level[0]

    return MerkleProof(
        leaf_index=leaf_index,
        leaf_hash=leaves[leaf_index],
        proof=proof_elements,
        root=root
    )


def verify_merkle_proof(
    leaf_hash: bytes,
    proof: List[ProofElement],
    expected_root: bytes
) -> bool:
    """
    Verify a Merkle inclusion proof.

    Args:
        leaf_hash: The leaf hash to verify
        proof: List of proof elements
        expected_root: Expected Merkle root

    Returns:
        True if proof is valid
    """
    current = leaf_hash

    for element in proof:
        if element.position == "left":
            current = sha256(element.hash + current)
        else:
            current = sha256(current + element.hash)

    return current == expected_root


def hex_to_bytes(hex_str: str) -> bytes:
    """Convert hex string to bytes."""
    return bytes.fromhex(hex_str)


def bytes_to_hex(data: bytes) -> str:
    """Convert bytes to hex string."""
    return data.hex()


# ============================================================================
# TEST
# ============================================================================

def run_tests():
    """Run Merkle tree tests."""
    print("=== Merkle Tree Tests ===\n")

    passed = 0
    failed = 0

    # Test 1: Single leaf
    print("Test: Single leaf (root = leaf)")
    leaf = sha256(b"single")
    root = compute_merkle_root([leaf])
    if root == leaf:
        print("  [PASS]")
        passed += 1
    else:
        print("  [FAIL]")
        failed += 1

    # Test 2: Two leaves
    print("Test: Two leaves")
    leaf0 = sha256(b"leaf0")
    leaf1 = sha256(b"leaf1")
    root = compute_merkle_root([leaf0, leaf1])
    expected = sha256(leaf0 + leaf1)
    if root == expected:
        print("  [PASS]")
        passed += 1
    else:
        print("  [FAIL]")
        failed += 1

    # Test 3: Four leaves
    print("Test: Four leaves (balanced)")
    leaves = [sha256(f"leaf{i}".encode()) for i in range(4)]
    root = compute_merkle_root(leaves)
    h01 = sha256(leaves[0] + leaves[1])
    h23 = sha256(leaves[2] + leaves[3])
    expected = sha256(h01 + h23)
    if root == expected:
        print("  [PASS]")
        passed += 1
    else:
        print("  [FAIL]")
        failed += 1

    # Test 4: Three leaves (odd count)
    print("Test: Three leaves (odd, duplicate last)")
    leaves = [sha256(f"leaf{i}".encode()) for i in range(3)]
    root = compute_merkle_root(leaves)
    h01 = sha256(leaves[0] + leaves[1])
    h22 = sha256(leaves[2] + leaves[2])  # Duplicated
    expected = sha256(h01 + h22)
    if root == expected:
        print("  [PASS]")
        passed += 1
    else:
        print("  [FAIL]")
        failed += 1

    # Test 5: Proof generation and verification
    print("Test: Proof generation and verification")
    leaves = [sha256(f"chunk{i}".encode()) for i in range(8)]
    root = compute_merkle_root(leaves)

    all_valid = True
    for i in range(8):
        proof = compute_merkle_proof(leaves, i)
        if not verify_merkle_proof(leaves[i], proof.proof, root):
            all_valid = False
            print(f"  [FAIL] Proof for leaf {i} failed")
            break

    if all_valid:
        print("  [PASS]")
        passed += 1
    else:
        failed += 1

    # Test 6: Invalid proof detection
    print("Test: Invalid proof rejection")
    leaves = [sha256(f"chunk{i}".encode()) for i in range(4)]
    root = compute_merkle_root(leaves)
    proof = compute_merkle_proof(leaves, 0)

    # Tamper with proof
    wrong_hash = sha256(b"wrong")
    if verify_merkle_proof(wrong_hash, proof.proof, root):
        print("  [FAIL] Should have rejected tampered proof")
        failed += 1
    else:
        print("  [PASS]")
        passed += 1

    # Test 7: Large tree
    print("Test: Large tree (1000 leaves)")
    leaves = [sha256(f"chunk{i}".encode()) for i in range(1000)]
    root = compute_merkle_root(leaves)

    # Verify random proofs
    import random
    random.seed(42)
    test_indices = random.sample(range(1000), 10)
    all_valid = True

    for i in test_indices:
        proof = compute_merkle_proof(leaves, i)
        if not verify_merkle_proof(leaves[i], proof.proof, root):
            all_valid = False
            break

    if all_valid:
        print("  [PASS]")
        passed += 1
    else:
        print("  [FAIL]")
        failed += 1

    print(f"\nResults: {passed} passed, {failed} failed")

    # Print example for test vectors
    print("\n=== Example Merkle Computations ===\n")

    # Two leaves example
    leaf0 = bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000000")
    leaf1 = bytes.fromhex("1111111111111111111111111111111111111111111111111111111111111111")
    root = compute_merkle_root([leaf0, leaf1])
    print(f"Two leaves (00...00, 11...11):")
    print(f"  Root: {root.hex()}")

    # Four leaves example
    leaves = [
        bytes.fromhex("aa" * 32),
        bytes.fromhex("bb" * 32),
        bytes.fromhex("cc" * 32),
        bytes.fromhex("dd" * 32),
    ]
    root = compute_merkle_root(leaves)
    h01 = sha256(leaves[0] + leaves[1])
    h23 = sha256(leaves[2] + leaves[3])
    print(f"\nFour leaves (aa..aa, bb..bb, cc..cc, dd..dd):")
    print(f"  H01: {h01.hex()}")
    print(f"  H23: {h23.hex()}")
    print(f"  Root: {root.hex()}")

    # Real chunk hashes from test vector
    chunk_hashes = [
        bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"),
        bytes.fromhex("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"),
        bytes.fromhex("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"),
        bytes.fromhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        bytes.fromhex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"),
    ]
    root = compute_merkle_root(chunk_hashes)
    print(f"\n5-chunk evidence Merkle root:")
    print(f"  Root: {root.hex()}")

    return failed == 0


if __name__ == "__main__":
    import sys
    success = run_tests()
    sys.exit(0 if success else 1)
