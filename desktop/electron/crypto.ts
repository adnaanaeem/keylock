/**
 * KeyLock crypto core.
 *
 * This module is the reference implementation of the KeyLock payload format.
 * The Android decryptor (android/keylock-decryptor) must produce byte-identical
 * results for the same inputs — see /test-vectors.json and its README note for
 * the known-answer test both sides are checked against.
 *
 * Format:
 *   certBytes     = raw bytes of the 64-hex-char certificate SHA-256 fingerprint
 *   salt          = random 16 bytes
 *   iv            = random 12 bytes (GCM standard nonce length)
 *   key           = PBKDF2-HMAC-SHA256(certBytes, salt, 100_000 iterations, 32 bytes)
 *   encryptedKey  = AES-256-GCM(plaintext, key, iv) with the 16-byte auth tag appended
 *   output        = base64(iv), base64(salt), base64(encryptedKey)
 *
 * Pure Node built-ins only (crypto module) — no network, no third-party deps.
 */

import { createCipheriv, createDecipheriv, pbkdf2Sync, randomBytes } from "crypto";

export const PBKDF2_ITERATIONS = 100_000;
export const KEY_LENGTH_BYTES = 32;
export const SALT_LENGTH_BYTES = 16;
export const IV_LENGTH_BYTES = 12;
export const AUTH_TAG_LENGTH_BYTES = 16;
export const FINGERPRINT_HEX_LENGTH = 64;

export class InvalidFingerprintError extends Error {
  constructor(fingerprint: string) {
    super(
      `Expected a 64-character hex SHA-256 fingerprint (colons/whitespace allowed as separators), got: "${fingerprint}"`
    );
    this.name = "InvalidFingerprintError";
  }
}

export class InvalidPayloadError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "InvalidPayloadError";
  }
}

export class DecryptionFailedError extends Error {
  constructor() {
    super(
      "Decryption failed: the fingerprint does not match what this payload was encrypted for, or the payload is corrupted (AES-GCM auth tag mismatch)."
    );
    this.name = "DecryptionFailedError";
  }
}

export interface EncryptedPayload {
  iv: string;
  salt: string;
  encryptedKey: string;
}

/** Normalizes a fingerprint string (strips colons/whitespace, lowercases) and returns its raw bytes. */
export function fingerprintToBytes(fingerprintHex: string): Buffer {
  const normalized = fingerprintHex.trim().replace(/[:\s]/g, "").toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new InvalidFingerprintError(fingerprintHex);
  }
  return Buffer.from(normalized, "hex");
}

function deriveKey(certBytes: Buffer, salt: Buffer): Buffer {
  return pbkdf2Sync(certBytes, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BYTES, "sha256");
}

/** Encrypts with an explicit salt/IV. Used by encrypt() (random) and the KAT self-test (fixed). */
export function encryptRaw(plaintext: string, certBytes: Buffer, salt: Buffer, iv: Buffer): Buffer {
  const key = deriveKey(certBytes, salt);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([ciphertext, authTag]);
}

export function encrypt(plaintext: string, fingerprintHex: string): EncryptedPayload {
  const certBytes = fingerprintToBytes(fingerprintHex);
  const salt = randomBytes(SALT_LENGTH_BYTES);
  const iv = randomBytes(IV_LENGTH_BYTES);
  const encryptedKey = encryptRaw(plaintext, certBytes, salt, iv);
  return {
    iv: iv.toString("base64"),
    salt: salt.toString("base64"),
    encryptedKey: encryptedKey.toString("base64"),
  };
}

export function decrypt(payload: EncryptedPayload, fingerprintHex: string): string {
  const certBytes = fingerprintToBytes(fingerprintHex);

  let iv: Buffer, salt: Buffer, combined: Buffer;
  try {
    iv = Buffer.from(payload.iv, "base64");
    salt = Buffer.from(payload.salt, "base64");
    combined = Buffer.from(payload.encryptedKey, "base64");
  } catch {
    throw new InvalidPayloadError("iv, salt, and encryptedKey must be valid base64 strings.");
  }

  if (iv.length !== IV_LENGTH_BYTES) {
    throw new InvalidPayloadError(`Invalid IV length: expected ${IV_LENGTH_BYTES} bytes, got ${iv.length}.`);
  }
  if (salt.length !== SALT_LENGTH_BYTES) {
    throw new InvalidPayloadError(`Invalid salt length: expected ${SALT_LENGTH_BYTES} bytes, got ${salt.length}.`);
  }
  if (combined.length <= AUTH_TAG_LENGTH_BYTES) {
    throw new InvalidPayloadError(
      `encryptedKey too short: must contain ciphertext plus a ${AUTH_TAG_LENGTH_BYTES}-byte auth tag.`
    );
  }

  const authTag = combined.subarray(combined.length - AUTH_TAG_LENGTH_BYTES);
  const ciphertext = combined.subarray(0, combined.length - AUTH_TAG_LENGTH_BYTES);
  const key = deriveKey(certBytes, salt);

  try {
    const decipher = createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(authTag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    return plaintext.toString("utf8");
  } catch {
    throw new DecryptionFailedError();
  }
}

export interface KnownAnswerVector {
  fingerprint: string;
  saltBase64: string;
  ivBase64: string;
  plaintext: string;
  expectedEncryptedKeyBase64: string;
}

/** Re-derives a KAT vector deterministically and checks it against the expected ciphertext. */
export function runSelfTest(vector: KnownAnswerVector): boolean {
  const certBytes = fingerprintToBytes(vector.fingerprint);
  const salt = Buffer.from(vector.saltBase64, "base64");
  const iv = Buffer.from(vector.ivBase64, "base64");
  const encryptedKey = encryptRaw(vector.plaintext, certBytes, salt, iv);
  return encryptedKey.toString("base64") === vector.expectedEncryptedKeyBase64;
}
