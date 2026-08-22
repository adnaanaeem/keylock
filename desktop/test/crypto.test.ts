import { describe, expect, it } from "vitest";
import { readFileSync } from "fs";
import { join } from "path";
import {
  decrypt,
  DecryptionFailedError,
  encrypt,
  fingerprintToBytes,
  InvalidFingerprintError,
  InvalidPayloadError,
  runSelfTest,
} from "../electron/crypto";

const kat = JSON.parse(readFileSync(join(__dirname, "..", "..", "test-vectors.json"), "utf8"));

describe("known-answer test vector", () => {
  it("reproduces the exact expected ciphertext from fixed inputs", () => {
    expect(runSelfTest(kat)).toBe(true);
  });

  it("decrypts the committed vector back to its known plaintext", () => {
    const plaintext = decrypt(
      { iv: kat.ivBase64, salt: kat.saltBase64, encryptedKey: kat.expectedEncryptedKeyBase64 },
      kat.fingerprint
    );
    expect(plaintext).toBe(kat.plaintext);
  });
});

describe("fingerprintToBytes", () => {
  it("accepts a bare 64-hex-char string", () => {
    expect(fingerprintToBytes(kat.fingerprint)).toHaveLength(32);
  });

  it("accepts colon- and whitespace-separated forms (keytool/apksigner style)", () => {
    const colonForm = kat.fingerprint.match(/.{2}/g).join(":").toUpperCase();
    expect(fingerprintToBytes(colonForm)).toEqual(fingerprintToBytes(kat.fingerprint));
  });

  it("rejects the wrong length", () => {
    expect(() => fingerprintToBytes("abcd")).toThrow(InvalidFingerprintError);
  });

  it("rejects non-hex characters", () => {
    expect(() => fingerprintToBytes("zz".repeat(32))).toThrow(InvalidFingerprintError);
  });
});

describe("encrypt/decrypt round trip", () => {
  const fingerprint = kat.fingerprint;

  it("round-trips an arbitrary secret", () => {
    const secret = "sk-test-1234567890abcdef";
    const payload = encrypt(secret, fingerprint);
    expect(decrypt(payload, fingerprint)).toBe(secret);
  });

  it("produces different ciphertext and iv/salt on every call (random nonce/salt)", () => {
    const a = encrypt("same-secret", fingerprint);
    const b = encrypt("same-secret", fingerprint);
    expect(a.iv).not.toBe(b.iv);
    expect(a.salt).not.toBe(b.salt);
    expect(a.encryptedKey).not.toBe(b.encryptedKey);
  });

  it("round-trips unicode plaintext", () => {
    const secret = "🔑 API-key-with-ünïcödé-日本語";
    const payload = encrypt(secret, fingerprint);
    expect(decrypt(payload, fingerprint)).toBe(secret);
  });

  it("fails to decrypt with the wrong fingerprint", () => {
    const payload = encrypt("secret", fingerprint);
    const wrongFingerprint = "f".repeat(64);
    expect(() => decrypt(payload, wrongFingerprint)).toThrow(DecryptionFailedError);
  });

  it("fails to decrypt a tampered ciphertext (auth tag check)", () => {
    const payload = encrypt("secret", fingerprint);
    const tampered = Buffer.from(payload.encryptedKey, "base64");
    tampered[0] ^= 0xff;
    expect(() =>
      decrypt({ ...payload, encryptedKey: tampered.toString("base64") }, fingerprint)
    ).toThrow(DecryptionFailedError);
  });

  it("rejects a malformed payload (wrong IV length) with a distinct error", () => {
    const payload = encrypt("secret", fingerprint);
    expect(() => decrypt({ ...payload, iv: Buffer.alloc(4).toString("base64") }, fingerprint)).toThrow(
      InvalidPayloadError
    );
  });
});
