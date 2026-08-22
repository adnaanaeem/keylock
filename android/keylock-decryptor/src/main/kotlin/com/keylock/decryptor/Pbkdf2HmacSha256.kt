package com.keylock.decryptor

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Hand-rolled PBKDF2-HMAC-SHA256 (RFC 8018 §5.2), operating on raw
 * [ByteArray]s end to end.
 *
 * This deliberately does NOT use `javax.crypto.spec.PBEKeySpec` +
 * `SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256")`: that API takes a
 * `char[]` password, and its internal byte conversion is not a plain UTF-8
 * encode of those chars — it silently derives a different key than the
 * desktop tool's `crypto.pbkdf2Sync(passwordBuffer, ...)` given the "same"
 * bytes. There's no exception when this happens, just a wrong key, which
 * then fails downstream as an opaque auth-tag mismatch. Working on
 * `ByteArray` via `Mac` directly avoids that whole class of bug and is
 * guaranteed byte-for-byte identical to Node's `pbkdf2Sync(Buffer, ...)`.
 *
 * Verify this against known-answer test vectors (see
 * [KeyLockDecryptorTest]) before trusting any change here.
 */
internal object Pbkdf2HmacSha256 {
    private const val HASH_LENGTH_BYTES = 32 // SHA-256 output size
    private const val ALGORITHM = "HmacSHA256"

    fun derive(password: ByteArray, salt: ByteArray, iterations: Int, keyLengthBytes: Int): ByteArray {
        require(iterations > 0) { "iterations must be positive" }
        require(keyLengthBytes > 0) { "keyLengthBytes must be positive" }

        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(password, ALGORITHM))

        val blockCount = (keyLengthBytes + HASH_LENGTH_BYTES - 1) / HASH_LENGTH_BYTES
        val output = ByteArray(blockCount * HASH_LENGTH_BYTES)

        for (blockIndex in 1..blockCount) {
            val block = f(mac, salt, iterations, blockIndex)
            System.arraycopy(block, 0, output, (blockIndex - 1) * HASH_LENGTH_BYTES, HASH_LENGTH_BYTES)
        }

        return output.copyOf(keyLengthBytes)
    }

    /** F(password, salt, iterations, blockIndex) = U1 xor U2 xor ... xor U_iterations, per RFC 8018 §5.2. */
    private fun f(mac: Mac, salt: ByteArray, iterations: Int, blockIndex: Int): ByteArray {
        val blockIndexBytes = byteArrayOf(
            (blockIndex ushr 24).toByte(),
            (blockIndex ushr 16).toByte(),
            (blockIndex ushr 8).toByte(),
            blockIndex.toByte()
        )

        mac.reset()
        var u = mac.doFinal(salt + blockIndexBytes) // U1 = HMAC(password, salt || INT_32_BE(blockIndex))
        val result = u.copyOf()

        for (i in 2..iterations) {
            mac.reset()
            u = mac.doFinal(u) // U_i = HMAC(password, U_{i-1})
            for (j in result.indices) {
                result[j] = (result[j].toInt() xor u[j].toInt()).toByte()
            }
        }

        return result
    }
}
