import type { KeyLockBridge } from "../electron/preload";

declare global {
  interface Window {
    keylock: KeyLockBridge;
  }
}

export {};
