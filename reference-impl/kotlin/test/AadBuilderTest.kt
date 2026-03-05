package com.evidence.contracts

import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.TestInstance
import java.io.File
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
class AadBuilderTest {

    data class TestVector(
        val id: String,
        val description: String,
        val inputs: Inputs,
        val expected: Expected
    )

    data class Inputs(
        val aeadSuiteId: Int,
        val hashSuiteId: Int,
        val evidenceId: String,
        val chunkIndex: Long,
        val manifestVer: Int,
        val policyHash: String
    )

    data class Expected(
        val aadHex: String,
        val aadLength: Int
    )

    data class TestVectorFile(
        val vectors: List<TestVector>
    )

    private lateinit var testVectors: List<TestVector>

    @BeforeAll
    fun loadTestVectors() {
        val vectorsFile = File("../../test-vectors/aad-computation.json")
        val json = vectorsFile.readText()
        val type = object : TypeToken<TestVectorFile>() {}.type
        val data: TestVectorFile = Gson().fromJson(json, type)
        testVectors = data.vectors
    }

    @Test
    fun `UUID to network bytes should be big-endian`() {
        val uuid = UUID.fromString("550e8400-e29b-41d4-a716-446655440000")
        val bytes = AadBuilder.uuidToNetworkBytes(uuid)
        val hex = bytes.toHex()
        assertEquals("550e8400e29b41d4a716446655440000", hex)
    }

    @Test
    fun `AAD for test vector aad-001`() {
        val vector = testVectors.find { it.id == "aad-001" }
            ?: throw AssertionError("Vector aad-001 not found")

        val aad = AadBuilder.build(
            aeadSuiteId = vector.inputs.aeadSuiteId.toByte(),
            hashSuiteId = vector.inputs.hashSuiteId.toByte(),
            evidenceId = UUID.fromString(vector.inputs.evidenceId),
            chunkIndex = vector.inputs.chunkIndex,
            manifestVer = vector.inputs.manifestVer,
            policyHash = vector.inputs.policyHash.hexToBytes()
        )

        assertEquals(60, aad.size)
        assertEquals(vector.expected.aadHex.lowercase(), aad.toHex())
    }

    @Test
    fun `AAD for test vector aad-002 (second chunk)`() {
        val vector = testVectors.find { it.id == "aad-002" }
            ?: throw AssertionError("Vector aad-002 not found")

        val aad = AadBuilder.build(
            aeadSuiteId = vector.inputs.aeadSuiteId.toByte(),
            hashSuiteId = vector.inputs.hashSuiteId.toByte(),
            evidenceId = UUID.fromString(vector.inputs.evidenceId),
            chunkIndex = vector.inputs.chunkIndex,
            manifestVer = vector.inputs.manifestVer,
            policyHash = vector.inputs.policyHash.hexToBytes()
        )

        assertEquals(vector.expected.aadHex.lowercase(), aad.toHex())
    }

    @Test
    fun `AAD for test vector aad-003 (large chunk index)`() {
        val vector = testVectors.find { it.id == "aad-003" }
            ?: throw AssertionError("Vector aad-003 not found")

        val aad = AadBuilder.build(
            aeadSuiteId = vector.inputs.aeadSuiteId.toByte(),
            hashSuiteId = vector.inputs.hashSuiteId.toByte(),
            evidenceId = UUID.fromString(vector.inputs.evidenceId),
            chunkIndex = vector.inputs.chunkIndex,
            manifestVer = vector.inputs.manifestVer,
            policyHash = vector.inputs.policyHash.hexToBytes()
        )

        assertEquals(vector.expected.aadHex.lowercase(), aad.toHex())
    }

    @Test
    fun `AAD should handle AES-256-GCM-SIV suite`() {
        val vector = testVectors.find { it.id == "aad-004" }
            ?: throw AssertionError("Vector aad-004 not found")

        val aad = AadBuilder.build(
            aeadSuiteId = vector.inputs.aeadSuiteId.toByte(),
            hashSuiteId = vector.inputs.hashSuiteId.toByte(),
            evidenceId = UUID.fromString(vector.inputs.evidenceId),
            chunkIndex = vector.inputs.chunkIndex,
            manifestVer = vector.inputs.manifestVer,
            policyHash = vector.inputs.policyHash.hexToBytes()
        )

        assertEquals(0x02, aad[0].toInt()) // AES-256-GCM-SIV
        assertEquals(vector.expected.aadHex.lowercase(), aad.toHex())
    }

    @Test
    fun `AAD should validate policyHash length`() {
        assertFailsWith<IllegalArgumentException> {
            AadBuilder.build(
                evidenceId = UUID.randomUUID(),
                chunkIndex = 0,
                policyHash = ByteArray(31) // Wrong length
            )
        }
    }

    @Test
    fun `AAD should reject negative chunk index`() {
        assertFailsWith<IllegalArgumentException> {
            AadBuilder.build(
                evidenceId = UUID.randomUUID(),
                chunkIndex = -1,
                policyHash = ByteArray(32)
            )
        }
    }

    @Test
    fun `All test vectors should pass`() {
        for (vector in testVectors) {
            val aad = AadBuilder.build(
                aeadSuiteId = vector.inputs.aeadSuiteId.toByte(),
                hashSuiteId = vector.inputs.hashSuiteId.toByte(),
                evidenceId = UUID.fromString(vector.inputs.evidenceId),
                chunkIndex = vector.inputs.chunkIndex,
                manifestVer = vector.inputs.manifestVer,
                policyHash = vector.inputs.policyHash.hexToBytes()
            )

            val computed = aad.toHex()
            val expected = vector.expected.aadHex.lowercase()

            assertEquals(expected, computed, "Failed for vector ${vector.id}")
        }
    }
}
