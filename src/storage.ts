/**
 * Storage adapters. The interface is a subset of the Web `Storage` API so that
 * `localStorage` / `sessionStorage` can be passed directly, and values may be
 * returned as promises so async stores (IndexedDB, React Native, KV) work too.
 */
export interface TokenStorage {
  getItem(key: string): string | null | undefined | Promise<string | null | undefined>
  setItem(key: string, value: string): void | Promise<void>
  removeItem(key: string): void | Promise<void>
}

/** In-memory storage. The default. Nothing survives a page reload or process restart. */
export function memoryStorage(): TokenStorage {
  const map = new Map<string, string>()
  return {
    getItem: (key) => map.get(key) ?? null,
    setItem: (key, value) => {
      map.set(key, value)
    },
    removeItem: (key) => {
      map.delete(key)
    },
  }
}

/**
 * Wrap a Web `Storage` (defaults to `localStorage`) and fall back to memory
 * when it is unavailable or throws (private mode, disabled cookies/storage,
 * some embedded browsers). Reads/writes are guarded so a quota error never breaks
 * the auth flow.
 */
export function browserStorage(storage?: Storage): TokenStorage {
  let store: Storage | null = null
  try {
    store = storage ?? (typeof localStorage !== 'undefined' ? localStorage : null)
    if (store) {
      const probe = '__supabase_oauth_client_probe__'
      store.setItem(probe, '1')
      store.removeItem(probe)
    }
  } catch {
    store = null
  }
  if (!store) return memoryStorage()
  const s = store
  const fallback = memoryStorage()
  return {
    getItem: (key) => {
      try {
        return s.getItem(key)
      } catch {
        return fallback.getItem(key)
      }
    },
    setItem: (key, value) => {
      try {
        s.setItem(key, value)
      } catch {
        fallback.setItem(key, value)
      }
    },
    removeItem: (key) => {
      try {
        s.removeItem(key)
      } catch {
        fallback.removeItem(key)
      }
    },
  }
}
