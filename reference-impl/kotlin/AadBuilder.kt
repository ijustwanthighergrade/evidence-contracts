package com.evidence.contracts

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.UUID

/**
 * AAD (Additional Authenticated Data) Builder
 *
 * Constructs the 60-byte AAD structure for AES-GCM encryption.
 * See specs/aad-format.md for specification.
 */
object AadBuilder {

    const val AAD_SIZE = 60
    const val AEAD_AES_256_GCM: Byte = 0x01
    const val AEAD_AES_256_GCM_SIV: Byte = 0x02
    const val HASH_SHA_256: Byte = 0x01
    const val HASH_SHA3_256: Byte = 0x02

    /**
     * Build AAD for a chunk.
     *
     * @param aeadSuiteId AEAD algorithm (1=AES-256-GCM, 2=AES-256-GCM-SIV)
     * @param hashSuiteId Hash algorithm (1=SHA-256, 2=SHA-3-256)
     * @param evidenceId Evidence UUID
     * @param chunkIndex 0-based chunk index
     * @param manifestVer Manifest version (e.g., 2)
     * @param policyHash 32-byte SHA-256 of policy document
     * @return 60-byte AAD
     */
    fun build(
        aeadSuiteId: Byte = AEAD_AES_256_GCM,
        hashSuiteId: Byte = HASH_SHA_256,
        evidenceId: UUID,
        chunkIndex: Long,
        manifestVer: Int = 2,
        policyHash: ByteArray
    ): ByteArray {
        require(policyHash.size == 32) { "policyHash must be 32 bytes" }
        require(chunkIndex >= 0) { "chunkIndex must be non-negative" }
        require(manifestVer in 0..65535) { "manifestVer must fit in uint16" }

        val buffer = ByteBuffer.allocate(AAD_SIZE)
        buffer.order(ByteOrder.BIG_ENDIAN)

        // Offset 0: aeadSuiteId (1 byte)
        buffer.put(aeadSuiteId)

        // Offset 1: hashSuiteId (1 byte)
        buffer.put(hashSuiteId)

        // Offset 2-17: evidenceId (16 bytes, network order)
        buffer.put(uuidToNetworkBytes(evidenceId))

        // Offset 18-25: chunkIndex (8 bytes, big-endian)
        buffer.putLong(chunkIndex)

        // Offset 26-27: manifestVer (2 bytes, big-endian)
        buffer.putShort(manifestVer.toShort())

        // Offset 28-59: policyHash (32 bytes)
        buffer.put(policyHash)

        return buffer.array()
    }

    /**
     * Convert UUID to network byte order (big-endian).
     *
     * WARNING: Do NOT use UUID.toString().replace("-","").hexToBytes()
     * as some platforms may use different byte orders.
     */
    fun uuidToNetworkBytes(uuid: UUID): ByteArray {
        val buffer = ByteBuffer.allocate(16)
        buffer.order(ByteOrder.BIG_ENDIAN)
        buffer.putLong(uuid.mostSignificantBits)
        buffer.putLong(uuid.leastSignificantBits)
        return buffer.array()
    }

    /**
     * Parse UUID from network byte order.
     */
    fun uuidFromNetworkBytes(bytes: ByteArray): UUID {
        require(bytes.size == 16) { "UUID bytes must be 16 bytes" }
        val buffer = ByteBuffer.wrap(bytes)
        buffer.order(ByteOrder.BIG_ENDIAN)
        return UUID(buffer.getLong(), buffer.getLong())
    }

    /**
     * Parse AAD back to components (for debugging/verification).
     */
    fun parse(aad: ByteArray): AadComponents {
        require(aad.size == AAD_SIZE) { "AAD must be $AAD_SIZE bytes" }

        val buffer = ByteBuffer.wrap(aad)
        buffer.order(ByteOrder.BIG_ENDIAN)

        val aeadSuiteId = buffer.get()
        val hashSuiteId = buffer.get()

        val uuidBytes = ByteArray(16)
        buffer.get(uuidBytes)
        val evidenceId = uuidFromNetworkBytes(uuidBytes)

        val chunkIndex = buffer.getLong()
        val manifestVer = buffer.getShort().toInt() and 0xFFFF

        val policyHash = ByteArray(32)
        buffer.get(policyHash)

        return AadComponents(
            aeadSuiteId = aeadSuiteId,
            hashSuiteId = hashSuiteId,
            evidenceId = evidenceId,
            chunkIndex = chunkIndex,
            manifestVer = manifestVer,
            policyHash = policyHash
        )
    }

    data class AadComponents(
        val aeadSuiteId: Byte,
        val hashSuiteId: Byte,
        val evidenceId: UUID,
        val chunkIndex: Long,
        val manifestVer: Int,
        val policyHash: ByteArray
    ) {
        override fun equals(other: Any?): Boolean {
            if (this === other) return true
            if (other !is AadComponents) return false
            return aeadSuiteId == other.aeadSuiteId &&
                    hashSuiteId == other.hashSuiteId &&
                    evidenceId == other.evidenceId &&
                    chunkIndex == other.chunkIndex &&
                    manifestVer == other.manifestVer &&
                    policyHash.contentEquals(other.policyHash)
        }

        override fun hashCode(): Int {
            var result = aeadSuiteId.toInt()
            result = 31 * result + hashSuiteId.toInt()
            result = 31 * result + evidenceId.hashCode()
            result = 31 * result + chunkIndex.hashCode()
            result = 31 * result + manifestVer
            result = 31 * result + policyHash.contentHashCode()
            return result
        }
    }
}

/**
 * Extension to convert hex string to ByteArray.
 */
fun String.hexToBytes(): ByteArray {
    require(length % 2 == 0) { "Hex string must have even length" }
    return chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

/**
 * Extension to convert ByteArray to hex string.
 */
fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }
