# KeyLock — handoff / continuity notes

Internal notes for resuming this project in a fresh Claude session (e.g. after switching accounts). Not user-facing — see [README.md](README.md) for that. Written 2026-09-15, HEAD at commit `5f7ad83`.

## What this is

KeyLock encrypts a secret (API key, token, etc.) so it can only be decrypted by an Android app signed with **one specific release keystore**. Two pieces in one repo:

- `desktop/` — offline Electron GUI that does the encrypting.
- `android/keylock-decryptor/` — dependency-free Kotlin library apps drop in to decrypt at runtime, using their own signing certificate.

Full usage/threat-model docs are in [README.md](README.md) — this file is about *how the project got here* and *what's still open*, which the README doesn't cover.

## Repo & access

- **https://github.com/adnaanaeem/keylock** — public, MIT license, owned by the user (Adnan Naeem, GitHub `adnaanaeem`).
- `gh` CLI is authenticated **on this machine** (Windows Credential Manager), not tied to any Claude.ai login — switching Claude accounts doesn't affect it. Still, **run `gh auth status` before pushing/creating a release from a new session** — if it's a different machine, they'll need to `gh auth login --web` again (device-code flow, user completes it in their own browser; don't attempt this for them without asking).
- v0.1.0 is the only release so far, pushed manually from this machine — no CI/GitHub Actions configured.

## Design decisions worth knowing before touching this code

1. **Fully offline by design.** `desktop/electron/main.ts` blocks every outbound request except `file://` via `session.defaultSession.webRequest.onBeforeRequest`, and `index.html`'s CSP is equally locked down. The **only** two exceptions — the About screen's live GitHub-profile fetch, and the startup auto-update check — run in the **main process only** (Node's global `fetch`, not the renderer's). This was a deliberate choice to preserve "your secret never touches the network" even though those two features do. Don't add renderer-side network calls without preserving this split.

2. **`keytool` auto-discovery.** `resolveKeytoolPath()` in `main.ts` checks `$JAVA_HOME` first, then falls back to Android Studio's bundled JBR at its well-known per-OS path (e.g. `C:\Program Files\Android\Android Studio\jbr\bin\keytool.exe` on Windows). Most Android devs have Studio but no standalone JDK on PATH — this was added after real friction testing keystore loading.

3. **Keystore password handling.** Passed to `keytool` via `-storepass:env` plus a scoped env var on the child process only — never a CLI arg (visible to other processes via the process list) or stdin (prompt-detection behavior is inconsistent across keytool/JDK vendors).

4. **`renderer.ts` / `about.ts` are plain scripts, not ES modules — this bit us once already.** Any top-level `import`/`export` makes `tsc` emit CommonJS `exports` boilerplate, which throws `ReferenceError: exports is not defined` in a sandboxed, `contextIsolation`-on/`nodeIntegration`-off renderer (no `exports` global exists there). Every button silently stopped working the first time this happened. Fix in place: these two files stay import/export-free; shared ambient types live in `desktop/src/global.d.ts`. **That filename matters** — a `.d.ts` sharing a basename with a `.ts` file in the same directory (e.g. `renderer.d.ts` next to `renderer.ts`) gets silently dropped from the TS program by `tsc`, so the type augmentation never applies. Keep it named `global.d.ts`.

5. **No native OS menu bar.** `Menu.setApplicationMenu(null)`; instead a hamburger button (☰, top-right of the header) calls `window.keylock.showMenu()` → IPC → `buildAppMenu().popup({ window: mainWindow })` in main. User's explicit request, not a default.

6. **Green "hacker terminal" theme**, `desktop/src/styles.css` — CSS custom properties only, dark-only (no light-mode branch), scanline overlay via `body::before`. Also explicitly requested.

7. **Gradle wrapper is pinned to 9.7.1, not 8.x — this was forced, not a preference.** Android Studio's bundled JBR here is JDK 25; Gradle 8.x tops out at JDK 24 for *running* Gradle itself (confirmed against Gradle's own compatibility table). AGP 8.5.0 + Kotlin 1.9.24 (unchanged) verified `BUILD SUCCESSFUL` under Gradle 9.7.1, but Gradle warned that some deprecated features AGP 8.5.0 uses will break under **Gradle 10** — not broken today, just something to revisit if AGP gets bumped later.

8. **`./gradlew :keylock-decryptor:test` needs `ANDROID_HOME` set** (correctly gitignored — every checkout needs its own). `JAVA_HOME` pointed at Android Studio's JBR works fine, e.g. on this machine: `JAVA_HOME="C:/Program Files/Android/Android Studio/jbr"`.

9. **`GITHUB_USERNAME`/`GITHUB_REPO` are hardcoded** in `desktop/electron/main.ts` (used for the About screen fetch, "View on GitHub" menu item, and the auto-updater's publish target) and duplicated in `desktop/package.json`'s `build.publish` block and the README badges. If the repo ever moves or gets renamed, all of those need updating together — there's no single source of truth for it currently.

## Current state

- **Desktop**: encrypt/decrypt/verify round-trip, load fingerprint from a keystore file (password + auto-detected alias if the keystore has more than one), About screen with live GitHub profile, hamburger menu, auto-update check on startup (`electron-updater`, GitHub provider). All 12 vitest tests pass (`cd desktop && npm test`).
- **Android**: `keylock-decryptor` — known-answer + round-trip tests pass (`./gradlew :keylock-decryptor:test`, verified `BUILD SUCCESSFUL`).
- **Release**: v0.1.0 on GitHub, Windows NSIS installer attached (`KeyLock Setup 0.1.0.exe`) plus `latest.yml`/`.blockmap` for the updater.
- Both `desktop/electron/crypto.ts` (Node) and `android/keylock-decryptor` (Kotlin) are cross-checked against the same known-answer vector in `test-vectors.json`.

## Known gaps — not done, not forgotten

- **No app icon** — electron-builder logs `default Electron icon is used, reason=application icon is not set`. Cosmetic, low priority.
- **Installer is unsigned.** No code-signing cert, so Windows SmartScreen will warn ("Windows protected your PC") on first run. Also relevant to auto-update reliability — signing is the norm for smooth `electron-updater` UX.
- **Auto-update has never been exercised end-to-end.** No v0.2.0 exists yet to update *to*, so the `checkForUpdatesAndNotify → update-downloaded → restart prompt` path is implemented but unverified in practice. First real test will be whenever the next release goes out.
- **Only built/tested on Windows.** `mac` (dmg) and `linux` (AppImage) targets are configured in `package.json` but never actually built or run.
- **No CI.** Every build/test/release so far was run manually from this machine.

## How to resume

```bash
git clone https://github.com/adnaanaeem/keylock.git
cd keylock/desktop && npm install && npm start
```

```bash
cd keylock/android
JAVA_HOME="<path to a JDK, e.g. Android Studio's jbr>" ANDROID_HOME="<path to Android SDK>" ./gradlew :keylock-decryptor:test
```

To cut a new release: `cd desktop && npm run dist` (electron-builder → `desktop/release/`), then `gh release create vX.Y.Z <installer> <installer>.blockmap latest.yml`.
