package com.keylock.decryptor

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.os.Build
import java.security.MessageDigest
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

private const val PBKDF2_ITERATIONS = 100_000
private const val KEY_LENGTH_BYTES = 32
private const val IV_LENGTH_BYTES = 12
private const val SALT_LENGTH_BYTES = 16
private const val AUTH_TAG_LENGTH_BITS = 128
private const val AUTH_TAG_LENGTH_BYTES = AUTH_TAG_LENGTH_BITS / 8
private const val GCM_TRANSFORMATION = "AES/GCM/NoPadding"

/** Base type for all KeyLock decryption failures, so callers can catch one type if they want. */
sealed class KeyLockDecryptionException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * The running app's signing certificate does not match the certificate this
 * payload was encrypted for (or the payload was tampered with — AES-GCM
 * can't tell the two apart, and neither can we). This is the expected
 * outcome for a debug/unofficial/re-signed build trying to read a
 * production secret; it is the feature working as designed, not a bug.
 */
class SigningCertificateMismatchException :
    KeyLockDecryptionException(
        "This build's signing certificate does not match the certificate the payload was encrypted for " +
            "(or the payload is corrupted). If this is a debug/CI/unofficial build, that is expected: " +
            "it should not be able to decrypt a secret encrypted for the release signing certificate."
    )

/** iv / salt / encryptedKey / fingerprint are missing, not valid base64/hex, or the wrong length. */
class MalformedPayloadException(message: String) : KeyLockDecryptionException(message)

/** Could not read the running app's own signing certificate via PackageManager. */
class SigningCertificateUnavailableException(message: String, cause: Throwable? = null) :
    KeyLockDecryptionException(message, cause)

/**
 * Decrypts secrets produced by the KeyLock desktop tool, using the running
 * app's own release-signing certificate as the decryption key material.
 *
 * Drop this file plus [Pbkdf2HmacSha256].kt into any Android project — no
 * other dependencies beyond `javax.crypto` / `java.security`, which ship
 * with the platform.
 *
 * See the KeyLock README for the full threat model. In short: this proves
 * "this binary was built with the matching release keystore," not "this
 * device/process hasn't been tampered with" — it is signing-certificate-bound
 * obfuscation, not a defense against a rooted device doing runtime memory
 * extraction.
 */
object KeyLockDecryptor {

    /**
     * Decrypts a KeyLock payload using the CURRENT app's signing certificate,
     * read at runtime via [PackageManager]. Throws
     * [SigningCertificateMismatchException] if this build isn't signed with
     * the certificate the payload was encrypted for.
     *
     * Note on signing certificate rotation: if your app uses APK signing
     * certificate rotation, this reads the certificate that directly signed
     * the currently-installed APK, not the full rotation lineage. Re-encrypt
     * secrets against the new certificate after rotating.
     */
    @Throws(KeyLockDecryptionException::class)
    fun decrypt(context: Context, ivBase64: String, saltBase64: String, encryptedKeyBase64: String): String {
        val fingerprint = getSigningCertificateSha256(context)
        return decryptWithFingerprint(fingerprint, ivBase64, saltBase64, encryptedKeyBase64)
    }

    /**
     * Same as [decrypt] but takes an explicit certificate SHA-256 fingerprint
     * (64 hex chars, colons/whitespace allowed) instead of reading it from
     * [PackageManager]. This is the pure-crypto path exercised by the
     * known-answer tests, and it's also usable directly if you already have
     * the fingerprint from elsewhere.
     */
    @Throws(KeyLockDecryptionException::class)
    fun decryptWithFingerprint(
        fingerprintHex: String,
        ivBase64: String,
        saltBase64: String,
        encryptedKeyBase64: String
    ): String {
        val certBytes = hexToCertBytes(fingerprintHex)

        val iv = decodeBase64Field(ivBase64, "iv")
        val salt = decodeBase64Field(saltBase64, "salt")
        val combined = decodeBase64Field(encryptedKeyBase64, "encryptedKey")

        if (iv.size != IV_LENGTH_BYTES) {
            throw MalformedPayloadException("Invalid IV length: expected $IV_LENGTH_BYTES bytes, got ${iv.size}.")
        }
        if (salt.size != SALT_LENGTH_BYTES) {
            throw MalformedPayloadException("Invalid salt length: expected $SALT_LENGTH_BYTES bytes, got ${salt.size}.")
        }
        if (combined.size <= AUTH_TAG_LENGTH_BYTES) {
            throw MalformedPayloadException(
                "encryptedKey too short: must contain ciphertext plus a $AUTH_TAG_LENGTH_BYTES-byte auth tag."
            )
        }

        val key = Pbkdf2HmacSha256.derive(certBytes, salt, PBKDF2_ITERATIONS, KEY_LENGTH_BYTES)

        return try {
            val cipher = Cipher.getInstance(GCM_TRANSFORMATION)
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(AUTH_TAG_LENGTH_BITS, iv))
            String(cipher.doFinal(combined), Charsets.UTF_8)
        } catch (e: Exception) {
            // AEADBadTagException (wrong key => wrong cert, or a tampered payload) and any
            // other cipher failure collapse to the same actionable message: the overwhelming
            // real-world cause is "this build isn't signed with the expected certificate."
            throw SigningCertificateMismatchException()
        }
    }

    /** Reads the running app's own signing certificate SHA-256, as lowercase hex with no separators. */
    @Throws(SigningCertificateUnavailableException::class)
    fun getSigningCertificateSha256(context: Context): String {
        val certificateDer = getSigningCertificate(context).toByteArray()
        val digest = MessageDigest.getInstance("SHA-256").digest(certificateDer)
        return digest.joinToString("") { "%02x".format(it) }
    }

    private fun getSigningCertificate(context: Context): Signature {
        val packageManager = context.packageManager
        val packageName = context.packageName
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNING_CERTIFICATES)
                val signers = packageInfo.signingInfo?.apkContentsSigners
                if (signers.isNullOrEmpty()) {
                    throw SigningCertificateUnavailableException("No signing certificates found for $packageName.")
                }
                return signers[0]
            } else {
                @Suppress("DEPRECATION")
                val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_SIGNATURES)
                @Suppress("DEPRECATION")
                val signatures = packageInfo.signatures
                if (signatures.isNullOrEmpty()) {
                    throw SigningCertificateUnavailableException("No signatures found for $packageName.")
                }
                return signatures[0]
            }
        } catch (e: PackageManager.NameNotFoundException) {
            throw SigningCertificateUnavailableException("Could not find package info for $packageName.", e)
        }
    }

    private fun hexToCertBytes(fingerprintHex: String): ByteArray {
        val normalized = fingerprintHex.trim().replace(":", "").replace(" ", "").lowercase()
        if (normalized.length != 64 || normalized.any { it !in "0123456789abcdef" }) {
            throw MalformedPayloadException(
                "Expected a 64-character hex SHA-256 fingerprint (colons/whitespace allowed as separators), " +
                    "got: \"$fingerprintHex\""
            )
        }
        val bytes = ByteArray(32)
        for (i in bytes.indices) {
            val hi = Character.digit(normalized[i * 2], 16)
            val lo = Character.digit(normalized[i * 2 + 1], 16)
            bytes[i] = ((hi shl 4) or lo).toByte()
        }
        return bytes
    }

    private fun decodeBase64Field(value: String, fieldName: String): ByteArray = try {
        Base64Util.decode(value)
    } catch (e: IllegalArgumentException) {
        throw MalformedPayloadException("$fieldName is not valid base64: ${e.message}")
    }
}

/**
 * Minimal standard (RFC 4648) base64 decoder, hand-rolled so this module has
 * no dependency on `android.util.Base64` (a no-op stub under plain JUnit
 * host tests unless you pull in Robolectric) or `java.util.Base64`
 * (API 26+, above this module's minSdk 21). Keeps `./gradlew test` fast,
 * dependency-free, and runnable without a device/emulator.
 */
private object Base64Util {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    private val DECODE_TABLE = IntArray(128) { -1 }.also {
        for ((index, char) in ALPHABET.withIndex()) it[char.code] = index
    }

    fun decode(input: String): ByteArray {
        val clean = input.trim()
        require(clean.isNotEmpty()) { "empty input" }
        require(clean.length % 4 == 0) { "base64 length must be a multiple of 4" }

        val padding = when {
            clean.endsWith("==") -> 2
            clean.endsWith("=") -> 1
            else -> 0
        }
        val core = clean.substring(0, clean.length - padding)
        require(core.all { it.code < 128 && DECODE_TABLE[it.code] >= 0 }) { "invalid base64 character" }

        val outputLength = (clean.length / 4) * 3 - padding
        val output = ByteArray(outputLength)
        var outIndex = 0
        var buffer = 0
        var bitsCollected = 0

        for (char in core) {
            buffer = (buffer shl 6) or DECODE_TABLE[char.code]
            bitsCollected += 6
            if (bitsCollected >= 8) {
                bitsCollected -= 8
                output[outIndex++] = ((buffer shr bitsCollected) and 0xFF).toByte()
            }
        }

        return output
    }
}
