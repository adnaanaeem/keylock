interface KeyEntry {
  id: string;
  name: string;
  fingerprint: string;
  iv: string;
  salt: string;
  encryptedKey: string;
  createdAt: number;
}

const keys: KeyEntry[] = [];
let selectedId: string | null = null;

function generateId(): string {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
}

function normalizeFingerprint(value: string): string {
  return value.trim().replace(/[:\s]/g, "").toLowerCase();
}

function isValidFingerprint(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(normalizeFingerprint(value));
}

function $<T extends HTMLElement>(id: string): T {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el as T;
}

const nameInput = $<HTMLInputElement>("key-name");
const plaintextInput = $<HTMLInputElement>("plaintext");
const togglePlaintextBtn = $<HTMLButtonElement>("toggle-plaintext-btn");
const fingerprintInput = $<HTMLInputElement>("fingerprint");
const fingerprintError = $<HTMLParagraphElement>("fingerprint-error");
const encryptBtn = $<HTMLButtonElement>("encrypt-btn");
const encryptError = $<HTMLParagraphElement>("encrypt-error");
const newKeyBtn = $<HTMLButtonElement>("new-key-btn");
const keyListEl = $<HTMLUListElement>("key-list");
const keyListEmpty = $<HTMLParagraphElement>("key-list-empty");

const outputPanel = $<HTMLDivElement>("output-panel");
const outIv = $<HTMLInputElement>("out-iv");
const outSalt = $<HTMLInputElement>("out-salt");
const outEncryptedKey = $<HTMLInputElement>("out-encryptedKey");
const exportStatus = $<HTMLParagraphElement>("export-status");
const loadIntoVerifyBtn = $<HTMLButtonElement>("load-into-verify-btn");

const verifyIv = $<HTMLInputElement>("verify-iv");
const verifySalt = $<HTMLInputElement>("verify-salt");
const verifyEncryptedKey = $<HTMLInputElement>("verify-encryptedKey");
const verifyFingerprint = $<HTMLInputElement>("verify-fingerprint");
const verifyBtn = $<HTMLButtonElement>("verify-btn");
const verifyResult = $<HTMLParagraphElement>("verify-result");

const selfTestBtn = $<HTMLButtonElement>("self-test-btn");
const selfTestStatus = $<HTMLSpanElement>("self-test-status");

const chooseKeystoreBtn = $<HTMLButtonElement>("choose-keystore-btn");
const keystoreFileLabel = $<HTMLSpanElement>("keystore-file-label");
const keystorePasswordInput = $<HTMLInputElement>("keystore-password");
const keystoreAliasRow = $<HTMLDivElement>("keystore-alias-row");
const keystoreAliasSelect = $<HTMLSelectElement>("keystore-alias-select");
const readKeystoreBtn = $<HTMLButtonElement>("read-keystore-btn");
const keystoreError = $<HTMLParagraphElement>("keystore-error");
const keystoreStatus = $<HTMLParagraphElement>("keystore-status");

let selectedKeystorePath: string | null = null;
let keystoreEntries: { alias: string; sha256Fingerprint: string }[] = [];

function renderKeyList(): void {
  keyListEl.innerHTML = "";
  keyListEmpty.classList.toggle("hidden", keys.length > 0);
  for (const entry of keys) {
    const li = document.createElement("li");
    li.textContent = entry.name || "(unnamed)";
    li.classList.toggle("active", entry.id === selectedId);
    li.addEventListener("click", () => selectKey(entry.id));
    keyListEl.appendChild(li);
  }
}

function selectKey(id: string): void {
  const entry = keys.find((k) => k.id === id);
  if (!entry) return;
  selectedId = id;
  nameInput.value = entry.name;
  fingerprintInput.value = entry.fingerprint;
  plaintextInput.value = "";
  showOutput(entry);
  renderKeyList();
}

function clearForm(): void {
  selectedId = null;
  nameInput.value = "";
  plaintextInput.value = "";
  fingerprintInput.value = "";
  hideOutput();
  renderKeyList();
}

function showOutput(entry: KeyEntry): void {
  outputPanel.classList.remove("hidden");
  outIv.value = entry.iv;
  outSalt.value = entry.salt;
  outEncryptedKey.value = entry.encryptedKey;
  exportStatus.textContent = "";
}

function hideOutput(): void {
  outputPanel.classList.add("hidden");
}

$<HTMLButtonElement>("menu-btn").addEventListener("click", () => {
  void window.keylock.showMenu();
});

togglePlaintextBtn.addEventListener("click", () => {
  plaintextInput.type = plaintextInput.type === "password" ? "text" : "password";
});

function validateFingerprintField(): void {
  const value = fingerprintInput.value;
  if (value.length === 0 || isValidFingerprint(value)) {
    fingerprintError.classList.add("hidden");
  } else {
    fingerprintError.textContent = "Expected 64 hex characters (colons/spaces are fine as separators).";
    fingerprintError.classList.remove("hidden");
  }
}

fingerprintInput.addEventListener("input", validateFingerprintField);

function applyFingerprintFromKeystore(entry: { alias: string; sha256Fingerprint: string }): void {
  fingerprintInput.value = entry.sha256Fingerprint;
  validateFingerprintField();
  keystoreStatus.textContent = `Loaded fingerprint from alias "${entry.alias}".`;
  keystoreStatus.classList.remove("error");
}

function basename(filePath: string): string {
  return filePath.split(/[\\/]/).pop() ?? filePath;
}

chooseKeystoreBtn.addEventListener("click", () => {
  void (async () => {
    const result = await window.keylock.pickKeystoreFile();
    if (result.path) {
      selectedKeystorePath = result.path;
      keystoreFileLabel.textContent = basename(result.path);
      keystoreError.classList.add("hidden");
      keystoreStatus.textContent = "";
      keystoreAliasRow.classList.add("hidden");
    }
  })();
});

readKeystoreBtn.addEventListener("click", () => {
  void (async () => {
    keystoreError.classList.add("hidden");
    keystoreStatus.textContent = "";
    keystoreAliasRow.classList.add("hidden");

    if (!selectedKeystorePath) {
      keystoreError.textContent = "Choose a keystore file first.";
      keystoreError.classList.remove("hidden");
      return;
    }
    if (!keystorePasswordInput.value) {
      keystoreError.textContent = "Enter the keystore password.";
      keystoreError.classList.remove("hidden");
      return;
    }

    readKeystoreBtn.disabled = true;
    keystoreStatus.textContent = "Reading keystore...";
    let result;
    try {
      result = await window.keylock.readKeystoreCertificates(selectedKeystorePath, keystorePasswordInput.value);
    } finally {
      readKeystoreBtn.disabled = false;
    }
    keystorePasswordInput.value = "";

    if (!result.ok) {
      keystoreStatus.textContent = "";
      keystoreError.textContent = result.error;
      keystoreError.classList.remove("hidden");
      return;
    }

    if (result.entries.length === 1) {
      applyFingerprintFromKeystore(result.entries[0]);
      return;
    }

    keystoreEntries = result.entries;
    keystoreAliasSelect.innerHTML = "";
    for (const entry of keystoreEntries) {
      const option = document.createElement("option");
      option.value = entry.alias;
      option.textContent = entry.alias;
      keystoreAliasSelect.appendChild(option);
    }
    keystoreAliasRow.classList.remove("hidden");
    applyFingerprintFromKeystore(keystoreEntries[0]);
  })();
});

keystoreAliasSelect.addEventListener("change", () => {
  const entry = keystoreEntries.find((e) => e.alias === keystoreAliasSelect.value);
  if (entry) applyFingerprintFromKeystore(entry);
});

newKeyBtn.addEventListener("click", clearForm);

encryptBtn.addEventListener("click", () => {
  void (async () => {
    encryptError.classList.add("hidden");
    const name = nameInput.value.trim();
    const plaintext = plaintextInput.value;
    const fingerprint = fingerprintInput.value;

    if (!plaintext) {
      encryptError.textContent = "Enter the secret value to encrypt.";
      encryptError.classList.remove("hidden");
      return;
    }
    if (!isValidFingerprint(fingerprint)) {
      encryptError.textContent = "Enter a valid 64-hex-character certificate SHA-256 fingerprint.";
      encryptError.classList.remove("hidden");
      return;
    }

    const result = await window.keylock.encrypt(plaintext, fingerprint);
    if (!result.ok) {
      encryptError.textContent = result.error;
      encryptError.classList.remove("hidden");
      return;
    }

    const entry: KeyEntry = {
      id: selectedId ?? generateId(),
      name: name || "(unnamed)",
      fingerprint: normalizeFingerprint(fingerprint),
      iv: result.payload.iv,
      salt: result.payload.salt,
      encryptedKey: result.payload.encryptedKey,
      createdAt: Date.now(),
    };

    const existingIndex = keys.findIndex((k) => k.id === entry.id);
    if (existingIndex >= 0) {
      keys[existingIndex] = entry;
    } else {
      keys.push(entry);
    }
    selectedId = entry.id;

    plaintextInput.value = "";
    showOutput(entry);
    renderKeyList();
  })();
});

function currentOutputEntry(): KeyEntry | undefined {
  return keys.find((k) => k.id === selectedId);
}

async function copyToClipboard(text: string, statusEl: HTMLElement, label: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    statusEl.textContent = `Copied ${label} to clipboard.`;
    statusEl.classList.remove("error");
    statusEl.classList.add("success");
  } catch (e) {
    statusEl.textContent = `Could not copy to clipboard: ${(e as Error).message}`;
    statusEl.classList.remove("success");
    statusEl.classList.add("error");
  }
}

document.querySelectorAll<HTMLButtonElement>(".copy-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    const targetId = btn.dataset.target;
    if (!targetId) return;
    const input = $<HTMLInputElement>(targetId);
    void copyToClipboard(input.value, exportStatus, targetId.replace("out-", ""));
  });
});

$<HTMLButtonElement>("export-json-btn").addEventListener("click", () => {
  const entry = currentOutputEntry();
  if (!entry) return;
  const json = JSON.stringify({ iv: entry.iv, salt: entry.salt, encryptedKey: entry.encryptedKey }, null, 2);
  void copyToClipboard(json, exportStatus, "JSON");
});

$<HTMLButtonElement>("export-firebase-btn").addEventListener("click", () => {
  const entry = currentOutputEntry();
  if (!entry) return;
  const json = JSON.stringify({ iv: entry.iv, salt: entry.salt, encryptedKey: entry.encryptedKey }, null, 2);
  void copyToClipboard(json, exportStatus, "Firebase RTDB payload").then(() => {
    exportStatus.textContent +=
      ` Save as payload.json, then run: firebase database:update /secrets/${entry.name} payload.json`;
  });
});

$<HTMLButtonElement>("export-firestore-btn").addEventListener("click", () => {
  const entry = currentOutputEntry();
  if (!entry) return;
  const docId = (entry.name || "secret").toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
  const snippet = [
    "// Save as setSecret.js and run: node setSecret.js",
    "// Requires firebase-admin configured with credentials for your project.",
    'const admin = require("firebase-admin");',
    "admin.initializeApp();",
    "",
    `admin.firestore().collection("secrets").doc("${docId}").set({`,
    `  iv: "${entry.iv}",`,
    `  salt: "${entry.salt}",`,
    `  encryptedKey: "${entry.encryptedKey}",`,
    "});",
  ].join("\n");
  void copyToClipboard(snippet, exportStatus, "Firestore document snippet");
});

loadIntoVerifyBtn.addEventListener("click", () => {
  const entry = currentOutputEntry();
  if (!entry) return;
  verifyIv.value = entry.iv;
  verifySalt.value = entry.salt;
  verifyEncryptedKey.value = entry.encryptedKey;
  verifyFingerprint.value = entry.fingerprint;
  verifyResult.textContent = "";
});

verifyBtn.addEventListener("click", () => {
  void (async () => {
    verifyResult.classList.remove("error", "success");
    const payload = { iv: verifyIv.value, salt: verifySalt.value, encryptedKey: verifyEncryptedKey.value };
    const fingerprint = verifyFingerprint.value;

    if (!payload.iv || !payload.salt || !payload.encryptedKey || !fingerprint) {
      verifyResult.textContent = "Fill in iv, salt, encryptedKey, and fingerprint first.";
      verifyResult.classList.add("error");
      return;
    }

    const result = await window.keylock.decrypt(payload, fingerprint);
    if (result.ok) {
      verifyResult.textContent = `Decrypted successfully: "${result.plaintext}"`;
      verifyResult.classList.add("success");
    } else {
      verifyResult.textContent = `Failed: ${result.error}`;
      verifyResult.classList.add("error");
    }
  })();
});

selfTestBtn.addEventListener("click", () => {
  void (async () => {
    selfTestStatus.textContent = "Running...";
    selfTestStatus.classList.remove("error", "success");
    const result = await window.keylock.selfTest();
    if (result.ok) {
      selfTestStatus.textContent = "Self-test passed: crypto core matches the known-answer vector.";
      selfTestStatus.classList.add("success");
    } else {
      selfTestStatus.textContent = `Self-test FAILED: ${result.error}`;
      selfTestStatus.classList.add("error");
    }
  })();
});

renderKeyList();
