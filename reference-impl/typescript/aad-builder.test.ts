import { buildAad, hexToBytes, bytesToHex, uuidToNetworkBytes } from './aad-builder';
import * as fs from 'fs';
import * as path from 'path';

interface TestVector {
  id: string;
  description: string;
  inputs: {
    aeadSuiteId: number;
    hashSuiteId: number;
    evidenceId: string;
    chunkIndex: number;
    manifestVer: number;
    policyHash: string;
  };
  expected: {
    aadHex: string;
    aadLength: number;
  };
}

interface TestVectorFile {
  vectors: TestVector[];
}

describe('AAD Builder', () => {
  let testVectors: TestVector[];

  beforeAll(() => {
    const vectorsPath = path.join(__dirname, '../../test-vectors/aad-computation.json');
    const data: TestVectorFile = JSON.parse(fs.readFileSync(vectorsPath, 'utf-8'));
    testVectors = data.vectors;
  });

  describe('UUID to network bytes', () => {
    it('should convert UUID to big-endian bytes', () => {
      const uuid = '550e8400-e29b-41d4-a716-446655440000';
      const bytes = uuidToNetworkBytes(uuid);
      const hex = bytesToHex(bytes);
      expect(hex).toBe('550e8400e29b41d4a716446655440000');
    });

    it('should handle all-zeros UUID', () => {
      const uuid = '00000000-0000-0000-0000-000000000000';
      const bytes = uuidToNetworkBytes(uuid);
      expect(bytes.length).toBe(16);
      expect(bytes.every(b => b === 0)).toBe(true);
    });
  });

  describe('AAD computation', () => {
    it('should produce correct AAD for test vector aad-001', () => {
      const vector = testVectors.find(v => v.id === 'aad-001');
      if (!vector) throw new Error('Vector aad-001 not found');

      const aad = buildAad({
        aeadSuiteId: vector.inputs.aeadSuiteId,
        hashSuiteId: vector.inputs.hashSuiteId,
        evidenceId: vector.inputs.evidenceId,
        chunkIndex: BigInt(vector.inputs.chunkIndex),
        manifestVer: vector.inputs.manifestVer,
        policyHash: hexToBytes(vector.inputs.policyHash),
      });

      expect(aad.length).toBe(60);
      expect(bytesToHex(aad)).toBe(vector.expected.aadHex.toLowerCase());
    });

    it('should produce correct AAD for test vector aad-002 (second chunk)', () => {
      const vector = testVectors.find(v => v.id === 'aad-002');
      if (!vector) throw new Error('Vector aad-002 not found');

      const aad = buildAad({
        aeadSuiteId: vector.inputs.aeadSuiteId,
        hashSuiteId: vector.inputs.hashSuiteId,
        evidenceId: vector.inputs.evidenceId,
        chunkIndex: BigInt(vector.inputs.chunkIndex),
        manifestVer: vector.inputs.manifestVer,
        policyHash: hexToBytes(vector.inputs.policyHash),
      });

      expect(bytesToHex(aad)).toBe(vector.expected.aadHex.toLowerCase());
    });

    it('should produce correct AAD for test vector aad-003 (large chunk index)', () => {
      const vector = testVectors.find(v => v.id === 'aad-003');
      if (!vector) throw new Error('Vector aad-003 not found');

      const aad = buildAad({
        aeadSuiteId: vector.inputs.aeadSuiteId,
        hashSuiteId: vector.inputs.hashSuiteId,
        evidenceId: vector.inputs.evidenceId,
        chunkIndex: BigInt(vector.inputs.chunkIndex),
        manifestVer: vector.inputs.manifestVer,
        policyHash: hexToBytes(vector.inputs.policyHash),
      });

      expect(bytesToHex(aad)).toBe(vector.expected.aadHex.toLowerCase());
    });

    it('should handle AES-256-GCM-SIV suite (aad-004)', () => {
      const vector = testVectors.find(v => v.id === 'aad-004');
      if (!vector) throw new Error('Vector aad-004 not found');

      const aad = buildAad({
        aeadSuiteId: vector.inputs.aeadSuiteId,
        hashSuiteId: vector.inputs.hashSuiteId,
        evidenceId: vector.inputs.evidenceId,
        chunkIndex: BigInt(vector.inputs.chunkIndex),
        manifestVer: vector.inputs.manifestVer,
        policyHash: hexToBytes(vector.inputs.policyHash),
      });

      expect(aad[0]).toBe(0x02); // AES-256-GCM-SIV
      expect(bytesToHex(aad)).toBe(vector.expected.aadHex.toLowerCase());
    });

    it('should validate policyHash length', () => {
      expect(() => {
        buildAad({
          evidenceId: '550e8400-e29b-41d4-a716-446655440000',
          chunkIndex: 0n,
          policyHash: new Uint8Array(31), // Wrong length
        });
      }).toThrow('policyHash must be 32 bytes');
    });

    it('should reject negative chunk index', () => {
      expect(() => {
        buildAad({
          evidenceId: '550e8400-e29b-41d4-a716-446655440000',
          chunkIndex: -1n,
          policyHash: new Uint8Array(32),
        });
      }).toThrow('chunkIndex must be non-negative');
    });
  });

  describe('All test vectors', () => {
    it('should pass all AAD test vectors', () => {
      for (const vector of testVectors) {
        const aad = buildAad({
          aeadSuiteId: vector.inputs.aeadSuiteId,
          hashSuiteId: vector.inputs.hashSuiteId,
          evidenceId: vector.inputs.evidenceId,
          chunkIndex: BigInt(vector.inputs.chunkIndex),
          manifestVer: vector.inputs.manifestVer,
          policyHash: hexToBytes(vector.inputs.policyHash),
        });

        const computed = bytesToHex(aad);
        const expected = vector.expected.aadHex.toLowerCase();

        expect(computed).toBe(expected);
      }
    });
  });
});
