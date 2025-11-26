const STORAGE_KEY = "sarif-viewer-session";

export function getOrCreateSessionId() {
  if (typeof window === "undefined") {
    return "";
  }
  const existing = window.localStorage.getItem(STORAGE_KEY);
  if (existing) {
    return existing;
  }
  const fresh = crypto.randomUUID();
  window.localStorage.setItem(STORAGE_KEY, fresh);
  return fresh;
}

