import { app, BrowserWindow, ipcMain, session, dialog, shell, Menu, MenuItemConstructorOptions } from "electron";
import { autoUpdater } from "electron-updater";
import { spawn } from "child_process";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { decrypt, encrypt, EncryptedPayload, runSelfTest } from "./crypto";
import { KNOWN_ANSWER_VECTOR } from "./knownAnswerVector";

/** Public GitHub handle shown on the About screen — the developer of this app, not the app's own account. */
const GITHUB_USERNAME = "adnaanaeem";
const GITHUB_REPO = "keylock";

interface AboutGithubProfile {
  login: string;
  name: string | null;
  avatarDataUri: string;
  bio: string | null;
  company: string | null;
  location: string | null;
  htmlUrl: string;
  publicRepos: number;
  followers: number;
}

/**
 * Fetches the developer's public GitHub profile plus their avatar, embedding
 * the avatar as a data: URI. This is the ONLY place in KeyLock that makes a
 * live network call, it only runs when the user opens Help > About, and it
 * runs in the main process — the renderer's CSP and the "no network but
 * file://" webRequest guard (see app.whenReady below) are untouched, so the
 * actual encrypt/decrypt UI still never talks to the network.
 */
async function fetchGithubProfile(username: string): Promise<AboutGithubProfile> {
  const res = await fetch(`https://api.github.com/users/${encodeURIComponent(username)}`, {
    headers: { Accept: "application/vnd.github+json", "User-Agent": "KeyLock-Desktop-App" },
  });
  if (!res.ok) {
    throw new Error(`GitHub API returned ${res.status} for user "${username}".`);
  }
  const data = (await res.json()) as {
    login: string;
    name: string | null;
    avatar_url: string;
    bio: string | null;
    company: string | null;
    location: string | null;
    html_url: string;
    public_repos: number;
    followers: number;
  };

  let avatarDataUri = "";
  try {
    const imgRes = await fetch(data.avatar_url);
    if (imgRes.ok) {
      const buf = Buffer.from(await imgRes.arrayBuffer());
      const contentType = imgRes.headers.get("content-type") || "image/png";
      avatarDataUri = `data:${contentType};base64,${buf.toString("base64")}`;
    }
  } catch {
    // Avatar is best-effort; the profile card still renders fine without it.
  }

  return {
    login: data.login,
    name: data.name,
    avatarDataUri,
    bio: data.bio,
    company: data.company,
    location: data.location,
    htmlUrl: data.html_url,
    publicRepos: data.public_repos,
    followers: data.followers,
  };
}

async function openAboutWindow(): Promise<void> {
  const aboutWin = new BrowserWindow({
    width: 420,
    height: 580,
    resizable: false,
    minimizable: false,
    maximizable: false,
    title: "About KeyLock",
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  aboutWin.setMenuBarVisibility(false);

  let profile: AboutGithubProfile | null = null;
  let error: string | null = null;
  try {
    profile = await fetchGithubProfile(GITHUB_USERNAME);
  } catch (e) {
    error = (e as Error).message;
  }

  const payload = encodeURIComponent(JSON.stringify({ profile, error, appVersion: app.getVersion() }));
  void aboutWin.loadFile(path.join(__dirname, "..", "src", "about.html"), { search: `data=${payload}` });
}

autoUpdater.autoDownload = true;
autoUpdater.on("update-downloaded", () => {
  void dialog
    .showMessageBox({
      type: "info",
      title: "Update ready",
      message: "A new version of KeyLock has been downloaded.",
      detail: "Restart now to apply it, or continue and it will apply the next time you quit.",
      buttons: ["Restart now", "Later"],
      defaultId: 0,
    })
    .then((result) => {
      if (result.response === 0) autoUpdater.quitAndInstall();
    });
});

function checkForUpdates(manual: boolean): void {
  if (!app.isPackaged) {
    if (manual) {
      void dialog.showMessageBox({
        type: "info",
        title: "Check for Updates",
        message: "Update checks only run in packaged builds, not in this dev run.",
      });
    }
    return;
  }
  autoUpdater.checkForUpdatesAndNotify().catch((err) => {
    if (manual) {
      dialog.showErrorBox("Update check failed", (err as Error).message);
    }
  });
}

function buildAppMenu(): Menu {
  const aboutItem: MenuItemConstructorOptions = { label: "About KeyLock", click: () => void openAboutWindow() };
  const checkUpdatesItem: MenuItemConstructorOptions = {
    label: "Check for Updates…",
    click: () => checkForUpdates(true),
  };
  const repoItem: MenuItemConstructorOptions = {
    label: "View on GitHub",
    click: () => void shell.openExternal(`https://github.com/${GITHUB_USERNAME}/${GITHUB_REPO}`),
  };

  const template: MenuItemConstructorOptions[] = [];

  if (process.platform === "darwin") {
    template.push({
      label: app.name,
      submenu: [aboutItem, { type: "separator" }, checkUpdatesItem, repoItem, { type: "separator" }, { role: "quit" }],
    });
    template.push({ label: "Edit", submenu: [{ role: "cut" }, { role: "copy" }, { role: "paste" }] });
  } else {
    template.push({
      label: "File",
      submenu: [{ role: "quit" }],
    });
  }

  template.push({
    label: "Help",
    submenu: process.platform === "darwin" ? [repoItem] : [aboutItem, checkUpdatesItem, { type: "separator" }, repoItem],
  });

  return Menu.buildFromTemplate(template);
}

/**
 * Finds a usable `keytool` binary. Prefers $JAVA_HOME, then falls back to the
 * JDK bundled with Android Studio (JBR) at its well-known per-OS install
 * location — Android developers overwhelmingly have Android Studio installed
 * even when a standalone JDK isn't on PATH. Falls back to the bare "keytool"
 * command (resolved via PATH) if none of those exist.
 */
function resolveKeytoolPath(): string {
  const keytoolBinary = process.platform === "win32" ? "keytool.exe" : "keytool";
  const candidates: string[] = [];

  if (process.env.JAVA_HOME) {
    candidates.push(path.join(process.env.JAVA_HOME, "bin", keytoolBinary));
  }

  if (process.platform === "win32") {
    candidates.push(
      path.join(process.env.ProgramFiles ?? "C:\\Program Files", "Android", "Android Studio", "jbr", "bin", keytoolBinary)
    );
  } else if (process.platform === "darwin") {
    candidates.push("/Applications/Android Studio.app/Contents/jbr/Contents/Home/bin/keytool");
  } else {
    candidates.push(
      "/opt/android-studio/jbr/bin/keytool",
      path.join(os.homedir(), "android-studio", "jbr", "bin", "keytool")
    );
  }

  for (const candidate of candidates) {
    if (fs.existsSync(candidate)) return candidate;
  }
  return "keytool";
}

export interface KeystoreCertificateEntry {
  alias: string;
  sha256Fingerprint: string;
}

/**
 * Runs `keytool -list -v` against a keystore to read its certificates' public
 * SHA-256 fingerprints. The password is passed via `-storepass:env` (a JDK 9+
 * keytool feature) and a scoped env var on the child process only, rather than
 * as a CLI argument (visible to other local processes/users via the process
 * list) or over stdin (prompt-detection behavior varies across keytool/JDK
 * vendors). Nothing here is persisted — the keystore path/password never leave
 * this machine and are not written to disk by KeyLock.
 */
function runKeytoolList(keystorePath: string, password: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const passwordEnvVar = "KEYLOCK_KEYTOOL_STOREPASS";
    const child = spawn(
      resolveKeytoolPath(),
      ["-list", "-v", "-keystore", keystorePath, "-storepass:env", passwordEnvVar],
      { env: { ...process.env, [passwordEnvVar]: password } }
    );

    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => (stdout += chunk.toString()));
    child.stderr.on("data", (chunk) => (stderr += chunk.toString()));

    child.on("error", (err) => {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") {
        reject(
          new Error(
            "keytool was not found on your PATH or in the bundled Android Studio JDK location. Install a JDK " +
              "(or set JAVA_HOME to one), or enter the fingerprint manually below."
          )
        );
      } else {
        reject(err);
      }
    });

    child.on("close", (code) => {
      if (code !== 0) {
        reject(new Error(stderr.trim() || `keytool exited with code ${code}.`));
      } else {
        resolve(stdout);
      }
    });
  });
}

/** Parses `keytool -list -v` output into one entry per alias with its SHA-256 fingerprint. */
function parseKeystoreEntries(keytoolOutput: string): KeystoreCertificateEntry[] {
  const entries: KeystoreCertificateEntry[] = [];
  const blocks = keytoolOutput.split(/\r?\nAlias name:\s*/).slice(1);
  for (const block of blocks) {
    const alias = block.split(/\r?\n/, 1)[0]?.trim();
    const shaMatch = block.match(/SHA256:\s*([0-9A-Fa-f:]+)/);
    if (!alias || !shaMatch) continue;
    const fingerprint = shaMatch[1].replace(/:/g, "").toLowerCase();
    if (/^[0-9a-f]{64}$/.test(fingerprint)) {
      entries.push({ alias, sha256Fingerprint: fingerprint });
    }
  }
  return entries;
}

function createWindow(): void {
  const win = new BrowserWindow({
    width: 1000,
    height: 760,
    minWidth: 760,
    minHeight: 560,
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  // index.html/styles.css are copied alongside the compiled renderer.js into
  // dist-electron/src by scripts/copy-static.cjs (see package.json "build"),
  // so the relative <script src="renderer.js"> in index.html resolves correctly.
  void win.loadFile(path.join(__dirname, "..", "src", "index.html"));
}

app.whenReady().then(() => {
  // Defense-in-depth for the "fully offline, no network calls" requirement:
  // block any outbound request that isn't loading the app's own local files.
  session.defaultSession.webRequest.onBeforeRequest((details, callback) => {
    const allowed =
      details.url.startsWith("file://") ||
      details.url.startsWith("devtools://") ||
      details.url.startsWith("chrome-extension://");
    callback({ cancel: !allowed });
  });

  ipcMain.handle("keylock:encrypt", (_event, plaintext: string, fingerprint: string) => {
    try {
      return { ok: true as const, payload: encrypt(plaintext, fingerprint) };
    } catch (e) {
      return { ok: false as const, error: (e as Error).message };
    }
  });

  ipcMain.handle("keylock:decrypt", (_event, payload: EncryptedPayload, fingerprint: string) => {
    try {
      return { ok: true as const, plaintext: decrypt(payload, fingerprint) };
    } catch (e) {
      return { ok: false as const, error: (e as Error).message };
    }
  });

  ipcMain.handle("keylock:pickKeystoreFile", async () => {
    const result = await dialog.showOpenDialog({
      title: "Select a keystore file",
      properties: ["openFile"],
    });
    const path = result.canceled || result.filePaths.length === 0 ? null : result.filePaths[0];
    return { ok: true as const, path };
  });

  ipcMain.handle(
    "keylock:readKeystoreCertificates",
    async (_event, keystorePath: string, password: string) => {
      try {
        const output = await runKeytoolList(keystorePath, password);
        const entries = parseKeystoreEntries(output);
        if (entries.length === 0) {
          return {
            ok: false as const,
            error: "No certificate entries with a SHA-256 fingerprint were found in this keystore.",
          };
        }
        return { ok: true as const, entries };
      } catch (e) {
        return { ok: false as const, error: (e as Error).message };
      }
    }
  );

  ipcMain.handle("keylock:selfTest", () => {
    try {
      const passed = runSelfTest(KNOWN_ANSWER_VECTOR);
      return passed
        ? { ok: true as const }
        : { ok: false as const, error: "Self-test ciphertext did not match the known-answer vector." };
    } catch (e) {
      return { ok: false as const, error: (e as Error).message };
    }
  });

  ipcMain.handle("keylock:openExternal", (_event, url: string) => {
    if (/^https:\/\//.test(url)) {
      void shell.openExternal(url);
    }
  });

  Menu.setApplicationMenu(buildAppMenu());
  createWindow();
  checkForUpdates(false);

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  if (process.platform !== "darwin") app.quit();
});
