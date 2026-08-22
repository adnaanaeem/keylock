import { contextBridge, ipcRenderer } from "electron";
import type { EncryptedPayload } from "./crypto";
import type { KeystoreCertificateEntry } from "./main";

export interface KeyLockBridge {
  encrypt: (
    plaintext: string,
    fingerprint: string
  ) => Promise<{ ok: true; payload: EncryptedPayload } | { ok: false; error: string }>;
  decrypt: (
    payload: EncryptedPayload,
    fingerprint: string
  ) => Promise<{ ok: true; plaintext: string } | { ok: false; error: string }>;
  selfTest: () => Promise<{ ok: true } | { ok: false; error: string }>;
  pickKeystoreFile: () => Promise<{ ok: true; path: string | null }>;
  readKeystoreCertificates: (
    keystorePath: string,
    password: string
  ) => Promise<{ ok: true; entries: KeystoreCertificateEntry[] } | { ok: false; error: string }>;
  openExternal: (url: string) => Promise<void>;
}

const bridge: KeyLockBridge = {
  encrypt: (plaintext, fingerprint) => ipcRenderer.invoke("keylock:encrypt", plaintext, fingerprint),
  decrypt: (payload, fingerprint) => ipcRenderer.invoke("keylock:decrypt", payload, fingerprint),
  selfTest: () => ipcRenderer.invoke("keylock:selfTest"),
  pickKeystoreFile: () => ipcRenderer.invoke("keylock:pickKeystoreFile"),
  readKeystoreCertificates: (keystorePath, password) =>
    ipcRenderer.invoke("keylock:readKeystoreCertificates", keystorePath, password),
  openExternal: (url) => ipcRenderer.invoke("keylock:openExternal", url),
};

contextBridge.exposeInMainWorld("keylock", bridge);
