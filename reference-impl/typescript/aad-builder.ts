/**
 * AAD (Additional Authenticated Data) Builder
 *
 * Constructs the 60-byte AAD structure for AES-GCM encryption.
 * See specs/aad-format.md for specification.
 */

export const AAD_SIZE = 60;

export const AEAD_SUITE = {
  AES_256_GCM: 0x01,
  AES_256_GCM_SIV: 0x02,
} as const;

export const HASH_SUITE = {
  SHA_256: 0x01,
  SHA3_256: 0x02,
} as const;

export interface AadParams {
  aeadSuiteId?: number;
  hashSuiteId?: number;
  evidenceId: string; // UUID string format
  chunkIndex: bigint;
  manifestVer?: number;
  policyHash: Uint8Array; // 32 bytes
}

/**
 * Build AAD for a chunk.
 */
export function buildAad(params: AadParams): Uint8Array {
  const {
    aeadSuiteId = AEAD_SUITE.AES_256_GCM,
    hashSuiteId = HASH_SUITE.SHA_256,
    evidenceId,
    chunkIndex,
    manifestVer = 2,
    policyHash,
  } = params;

  if (policyHash.length !== 32) {
    throw new Error('policyHash must be 32 bytes');
  }
  if (chunkIndex < 0n) {
    throw new Error('chunkIndex must be non-negative');
  }
  if (manifestVer < 0 || manifestVer > 65535) {
    throw new Error('manifestVer must fit in uint16');
  }

  const buffer = new ArrayBuffer(AAD_SIZE);
  const view = new DataView(buffer);
  const bytes = new Uint8Array(buffer);

  let offset = 0;

  // Offset 0: aeadSuiteId (1 byte)
  view.setUint8(offset++, aeadSuiteId);

  // Offset 1: hashSuiteId (1 byte)
  view.setUint8(offset++, hashSuiteId);

  // Offset 2-17: evidenceId (16 bytes, network order)
  const uuidBytes = uuidToNetworkBytes(evidenceId);
  bytes.set(uuidBytes, offset);
  offset += 16;

  // Offset 18-25: chunkIndex (8 bytes, big-endian)
  view.setBigUint64(offset, chunkIndex, false); // false = big-endian
  offset += 8;

  // Offset 26-27: manifestVer (2 bytes, big-endian)
  view.setUint16(offset, manifestVer, false);
  offset += 2;

  // Offset 28-59: policyHash (32 bytes)
  bytes.set(policyHash, offset);

  return bytes;
}

/**
 * Convert UUID string to network byte order (big-endian).
 *
 * WARNING: Do NOT use libraries that may use different byte orders.
 */
export function uuidToNetworkBytes(uuid: string): Uint8Array {
  // Remove dashes and validate
  const hex = uuid.replace(/-/g, '');
  if (hex.length !== 32) {
    throw new Error('Invalid UUID format');
  }
  if (!/^[0-9a-fA-F]{32}$/.test(hex)) {
    throw new Error('Invalid UUID characters');
  }

  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert network byte order to UUID string.
 */
export function uuidFromNetworkBytes(bytes: Uint8Array): string {
  if (bytes.length !== 16) {
    throw new Error('UUID bytes must be 16 bytes');
  }

  const hex = Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');

  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

/**
 * Parse AAD back to components (for debugging/verification).
 */
export interface AadComponents {
  aeadSuiteId: number;
  hashSuiteId: number;
  evidenceId: string;
  chunkIndex: bigint;
  manifestVer: number;
  policyHash: Uint8Array;
}

export function parseAad(aad: Uint8Array): AadComponents {
  if (aad.length !== AAD_SIZE) {
    throw new Error(`AAD must be ${AAD_SIZE} bytes`);
  }

  const view = new DataView(aad.buffer, aad.byteOffset, aad.byteLength);

  let offset = 0;

  const aeadSuiteId = view.getUint8(offset++);
  const hashSuiteId = view.getUint8(offset++);

  const uuidBytes = aad.slice(offset, offset + 16);
  const evidenceId = uuidFromNetworkBytes(uuidBytes);
  offset += 16;

  const chunkIndex = view.getBigUint64(offset, false);
  offset += 8;

  const manifestVer = view.getUint16(offset, false);
  offset += 2;

  const policyHash = aad.slice(offset, offset + 32);

  return {
    aeadSuiteId,
    hashSuiteId,
    evidenceId,
    chunkIndex,
    manifestVer,
    policyHash,
  };
}

/**
 * Convert hex string to Uint8Array.
 */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have even length');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substring(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

/**
 * Convert Uint8Array to hex string.
 */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}
