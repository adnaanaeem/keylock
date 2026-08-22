// Regenerates /test-vectors.json from fixed inputs. This is the canonical
// generator for the known-answer test (KAT) that both the desktop crypto
// core (desktop/test/crypto.test.ts) and the Android decryptor
// (android/keylock-decryptor/.../KeyLockDecryptorTest.kt) are checked
// against. Run with: node scripts/generate-test-vectors.cjs
//
// Deliberately does NOT import from ../electron/crypto.ts — it re-implements
// the same primitive calls standalone so it stays a from-scratch reference,
// not a copy that could hide a bug shared by both.
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");

const FINGERPRINT_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
const SALT_HEX = "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf";
const IV_HEX = "b0b1b2b3b4b5b6b7b8b9babb";
const PLAINTEXT = "KeyLock-KAT-vector-secret-value-2026";

const certBytes = Buffer.from(FINGERPRINT_HEX, "hex");
const salt = Buffer.from(SALT_HEX, "hex");
const iv = Buffer.from(IV_HEX, "hex");

const key = crypto.pbkdf2Sync(certBytes, salt, 100_000, 32, "sha256");
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
const ciphertext = Buffer.concat([cipher.update(PLAINTEXT, "utf8"), cipher.final()]);
const authTag = cipher.getAuthTag();
const encryptedKey = Buffer.concat([ciphertext, authTag]);

const vector = {
  description:
    "Known-answer test (KAT) vector. Fixed inputs -> fixed expected ciphertext. Both the desktop (Node) and Android (Kotlin) implementations must reproduce expectedEncryptedKeyBase64 exactly. Do not treat fingerprint as a real app's certificate — it is a synthetic incrementing-byte pattern chosen only for reproducibility.",
  fingerprint: FINGERPRINT_HEX,
  saltBase64: salt.toString("base64"),
  ivBase64: iv.toString("base64"),
  plaintext: PLAINTEXT,
  expectedEncryptedKeyBase64: encryptedKey.toString("base64"),
  params: {
    pbkdf2Iterations: 100000,
    keyLengthBytes: 32,
    saltLengthBytes: 16,
    ivLengthBytes: 12,
    authTagLengthBytes: 16,
  },
};

const outPath = path.join(__dirname, "..", "..", "test-vectors.json");
fs.writeFileSync(outPath, JSON.stringify(vector, null, 2) + "\n");
console.log("Wrote", outPath);
console.log(JSON.stringify(vector, null, 2));
