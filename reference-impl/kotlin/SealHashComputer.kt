package com.evidence.contracts

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.UUID

/**
 * sealHash Computer
 *
 * Computes the binding hash that ties all evidence components together.
 * See specs/seal-hash.md for specification.
 */
object SealHashComputer {

    const val SEAL_INPUT_SIZE = 192  // 6 × 32 bytes

    /**
     * Compute sealHash from all components.
     *
     * @param manifestHash SHA-256 of JCS(manifest without integrity)
     * @param mediaPlaintextHash SHA-256 of original media
     * @param chunkMerkleRoot Merkle root of ciphertext chunk hashes
     * @param finalEventHash Hash of final event in chain
     * @param sessionBindingHash Hash of session binding data
     * @param policyHash SHA-256 of policy document
     * @return 32-byte sealHash
     */
    fun compute(
        manifestHash: ByteArray,
        mediaPlaintextHash: ByteArray,
        chunkMerkleRoot: ByteArray,
        finalEventHash: ByteArray,
        sessionBindingHash: ByteArray,
        policyHash: ByteArray
    ): ByteArray {
        require(manifestHash.size == 32) { "manifestHash must be 32 bytes" }
        require(mediaPlaintextHash.size == 32) { "mediaPlaintextHash must be 32 bytes" }
        require(chunkMerkleRoot.size == 32) { "chunkMerkleRoot must be 32 bytes" }
        require(finalEventHash.size == 32) { "finalEventHash must be 32 bytes" }
        require(sessionBindingHash.size == 32) { "sessionBindingHash must be 32 bytes" }
        require(policyHash.size == 32) { "policyHash must be 32 bytes" }

        val buffer = ByteBuffer.allocate(SEAL_INPUT_SIZE)
        buffer.put(manifestHash)        // 0-31
        buffer.put(mediaPlaintextHash)  // 32-63
        buffer.put(chunkMerkleRoot)     // 64-95
        buffer.put(finalEventHash)      // 96-127
        buffer.put(sessionBindingHash)  // 128-159
        buffer.put(policyHash)          // 160-191

        return sha256(buffer.array())
    }

    /**
     * Compute sessionBindingHash.
     *
     * @param sessionId Server-issued session UUID
     * @param serverIssuedAtMs Server timestamp (Unix epoch milliseconds)
     * @param appSignatureDigest 32-byte SHA-256 of app signing cert
     * @param deviceKeyId UTF-8 string identifier for device key
     * @return 32-byte sessionBindingHash
     */
    fun computeSessionBinding(
        sessionId: UUID,
        serverIssuedAtMs: Long,
        appSignatureDigest: ByteArray,
        deviceKeyId: String
    ): ByteArray {
        require(appSignatureDigest.size == 32) { "appSignatureDigest must be 32 bytes" }

        val deviceKeyIdBytes = deviceKeyId.toByteArray(Charsets.UTF_8)
        require(deviceKeyIdBytes.size <= 65535) { "deviceKeyId too long" }

        // 16 (UUID) + 8 (timestamp) + 32 (digest) + 2 (length prefix) + deviceKeyId bytes
        val bufferSize = 16 + 8 + 32 + 2 + deviceKeyIdBytes.size
        val buffer = ByteBuffer.allocate(bufferSize)
        buffer.order(ByteOrder.BIG_ENDIAN)

        // sessionId (16 bytes, network order)
        buffer.put(AadBuilder.uuidToNetworkBytes(sessionId))

        // serverIssuedAtMs (8 bytes, big-endian)
        buffer.putLong(serverIssuedAtMs)

        // appSignatureDigest (32 bytes)
        buffer.put(appSignatureDigest)

        // deviceKeyId (length-prefixed: 2 bytes length + UTF-8 bytes)
        buffer.putShort(deviceKeyIdBytes.size.toShort())
        buffer.put(deviceKeyIdBytes)

        return sha256(buffer.array())
    }

    /**
     * Verify a sealHash matches expected value.
     * Uses constant-time comparison to prevent timing attacks.
     */
    fun verify(
        expected: ByteArray,
        manifestHash: ByteArray,
        mediaPlaintextHash: ByteArray,
        chunkMerkleRoot: ByteArray,
        finalEventHash: ByteArray,
        sessionBindingHash: ByteArray,
        policyHash: ByteArray
    ): Boolean {
        val computed = compute(
            manifestHash,
            mediaPlaintextHash,
            chunkMerkleRoot,
            finalEventHash,
            sessionBindingHash,
            policyHash
        )
        return MessageDigest.isEqual(expected, computed)
    }

    private fun sha256(data: ByteArray): ByteArray {
        return MessageDigest.getInstance("SHA-256").digest(data)
    }
}

/**
 * Merkle tree utilities for chunk hashing.
 */
object MerkleTree {

    /**
     * Compute Merkle root from leaf hashes.
     *
     * @param leaves List of 32-byte leaf hashes
     * @return 32-byte Merkle root
     */
    fun computeRoot(leaves: List<ByteArray>): ByteArray {
        require(leaves.isNotEmpty()) { "At least one leaf required" }
        leaves.forEach { require(it.size == 32) { "Each leaf must be 32 bytes" } }

        if (leaves.size == 1) {
            return leaves[0].copyOf()
        }

        var currentLevel = leaves.map { it.copyOf() }

        while (currentLevel.size > 1) {
            val nextLevel = mutableListOf<ByteArray>()

            for (i in currentLevel.indices step 2) {
                val left = currentLevel[i]
                val right = if (i + 1 < currentLevel.size) {
                    currentLevel[i + 1]
                } else {
                    // Odd number: duplicate last
                    left
                }
                nextLevel.add(hashPair(left, right))
            }

            currentLevel = nextLevel
        }

        return currentLevel[0]
    }

    /**
     * Generate inclusion proof for a leaf.
     *
     * @param leaves All leaf hashes
     * @param leafIndex Index of target leaf
     * @return List of (position, hash) pairs
     */
    fun generateProof(leaves: List<ByteArray>, leafIndex: Int): List<ProofElement> {
        require(leafIndex in leaves.indices) { "leafIndex out of range" }

        val proof = mutableListOf<ProofElement>()
        var currentLevel = leaves.map { it.copyOf() }
        var currentIndex = leafIndex

        while (currentLevel.size > 1) {
            val siblingIndex = if (currentIndex % 2 == 0) currentIndex + 1 else currentIndex - 1
            val position = if (currentIndex % 2 == 0) Position.RIGHT else Position.LEFT

            if (siblingIndex < currentLevel.size) {
                proof.add(ProofElement(position, currentLevel[siblingIndex].copyOf()))
            } else {
                // Odd case: sibling is self
                proof.add(ProofElement(position, currentLevel[currentIndex].copyOf()))
            }

            // Build next level
            val nextLevel = mutableListOf<ByteArray>()
            for (i in currentLevel.indices step 2) {
                val left = currentLevel[i]
                val right = if (i + 1 < currentLevel.size) currentLevel[i + 1] else left
                nextLevel.add(hashPair(left, right))
            }

            currentLevel = nextLevel
            currentIndex /= 2
        }

        return proof
    }

    /**
     * Verify inclusion proof.
     */
    fun verifyProof(leaf: ByteArray, proof: List<ProofElement>, expectedRoot: ByteArray): Boolean {
        var current = leaf.copyOf()

        for (element in proof) {
            current = when (element.position) {
                Position.LEFT -> hashPair(element.hash, current)
                Position.RIGHT -> hashPair(current, element.hash)
            }
        }

        return MessageDigest.isEqual(current, expectedRoot)
    }

    private fun hashPair(left: ByteArray, right: ByteArray): ByteArray {
        val combined = ByteArray(64)
        System.arraycopy(left, 0, combined, 0, 32)
        System.arraycopy(right, 0, combined, 32, 32)
        return MessageDigest.getInstance("SHA-256").digest(combined)
    }

    enum class Position { LEFT, RIGHT }

    data class ProofElement(val position: Position, val hash: ByteArray) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is ProofElement) return false
            return position == other.position && hash.contentEquals(other.hash)
        }

        override fun hashCode(): Int {
            return 31 * position.hashCode() + hash.contentHashCode()
        }
    }
}
