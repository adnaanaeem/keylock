# KeyLock

Encrypt a secret (an API key, a token, anything) so that it can only be decrypted by an Android app signed with **one specific release keystore**. The encrypted output is safe to commit, ship in your APK, or store in Firebase — without your desktop, your CI, or a MITM ever seeing the plaintext.

KeyLock is two pieces:

- **`desktop/`** — an offline Electron GUI that encrypts a secret against a signing certificate's SHA-256 fingerprint (typed in, or read directly from a keystore file).
- **`android/keylock-decryptor`** — a small, dependency-free Kotlin library you drop into your Android app. At runtime it reads the *running app's own* signing certificate and uses it to decrypt the payload KeyLock produced.

## Threat model

This proves **"this binary was built with the matching release keystore"** — it does not prove "this device/process hasn't been tampered with." It is signing-certificate-bound obfuscation, not a defense against a rooted device doing runtime memory extraction. Anyone who can extract memory from a legitimately-signed, running instance of your app can recover the secret — that has always been true of any client-side secret. What this *does* stop is a debug build, a re-signed/repackaged APK, or an unrelated app from decrypting your key, since AES-GCM will simply fail to authenticate against the wrong certificate fingerprint.

The certificate SHA-256 fingerprint is **public** (it ships inside every APK signed with it) — never treat it as a secret. The keystore file and its password never leave your machine; KeyLock only ever reads the public certificate out of it.

## Payload format

```
certBytes     = raw bytes of the 64-hex-char certificate SHA-256 fingerprint
salt          = random 16 bytes
iv            = random 12 bytes (GCM standard nonce length)
key           = PBKDF2-HMAC-SHA256(certBytes, salt, 100_000 iterations, 32 bytes)
encryptedKey  = AES-256-GCM(plaintext, key, iv) with the 16-byte auth tag appended
output        = { iv: base64, salt: base64, encryptedKey: base64 }
```

The desktop (`desktop/electron/crypto.ts`) and Android (`android/keylock-decryptor`) implementations are cross-checked against a shared known-answer test vector in [`test-vectors.json`](test-vectors.json), regenerated via `desktop/scripts/generate-test-vectors.cjs`.

## Using the desktop app

```bash
cd desktop
npm install
npm start
```

1. Paste the secret you want to protect.
2. Get the certificate fingerprint — either paste it manually (`keytool -list -v -keystore your.jks -alias yourAlias`, or `apksigner verify --print-certs app-release.apk`), or click **Load from keystore file** and pick the `.jks`/`.keystore`/`.p12` file directly (KeyLock shells out to your local `keytool` — including the JDK bundled with Android Studio — to read the fingerprint; the password is passed via a scoped environment variable, never as a CLI argument or written to disk).
3. Click **Encrypt**, then **Use this output in "Verify round-trip"** to confirm it decrypts before you ship it anywhere.

The app is offline by design: its `Content-Security-Policy` and a main-process network guard block every outbound request except loading its own local files. The one deliberate exception is the **About** screen, which does a single live fetch of the developer's public GitHub profile, and the optional auto-updater — both run in the main process only, so the actual encrypt/decrypt UI never touches the network.

## Using the Android library

Drop `KeyLockDecryptor.kt` and `Pbkdf2HmacSha256.kt` into your app (or depend on the `keylock-decryptor` module) — no dependencies beyond `javax.crypto`/`java.security`, which ship with the platform.

```kotlin
val secret = KeyLockDecryptor.decrypt(
    context = context,
    ivBase64 = payload.iv,
    saltBase64 = payload.salt,
    encryptedKeyBase64 = payload.encryptedKey,
)
```

This reads the *running* app's own signing certificate via `PackageManager` and throws `SigningCertificateMismatchException` if it doesn't match what the payload was encrypted for — which is the expected, correct outcome for a debug/CI/unofficial build.

## Building an installer

```bash
cd desktop
npm run dist
```

Produces a Windows NSIS installer / macOS DMG / Linux AppImage via `electron-builder`, depending on the host platform.

## Development

```bash
cd desktop
npm install
npm test              # crypto known-answer + round-trip tests (vitest)
npm run build          # type-check + compile
```

```bash
cd android
./gradlew :keylock-decryptor:test   # JVM known-answer tests, no device/emulator needed
```

## License

MIT — see [LICENSE](LICENSE).
