type Entry<T> = { value: T; createdAt: number; lastSeen: number };

export type TtlOptions = {
  /** Maximum lifetime from creation, in milliseconds. */
  absoluteMs: number;
  /** Maximum time between uses, in milliseconds. */
  idleMs: number;
  now?: () => number;
};

/** A small in-memory store with absolute and idle expiry. Nothing is written to disk. */
export class TtlStore<T> {
  private readonly entries = new Map<string, Entry<T>>();
  private readonly now: () => number;

  constructor(private readonly options: TtlOptions) {
    this.now = options.now ?? Date.now;
  }

  set(id: string, value: T) {
    const t = this.now();
    this.entries.set(id, { value, createdAt: t, lastSeen: t });
    this.sweep();
  }

  /** Returns the value and refreshes its idle timer, or undefined if missing or expired. */
  get(id: string): T | undefined {
    const entry = this.entries.get(id);
    if (!entry) return undefined;
    const t = this.now();
    if (t - entry.createdAt > this.options.absoluteMs || t - entry.lastSeen > this.options.idleMs) {
      this.entries.delete(id);
      return undefined;
    }
    entry.lastSeen = t;
    return entry.value;
  }

  /** Returns and removes the value in one step. */
  take(id: string): T | undefined {
    const value = this.get(id);
    this.entries.delete(id);
    return value;
  }

  delete(id: string) {
    this.entries.delete(id);
  }

  get size() {
    return this.entries.size;
  }

  private sweep() {
    const t = this.now();
    for (const [id, e] of this.entries) {
      if (t - e.createdAt > this.options.absoluteMs || t - e.lastSeen > this.options.idleMs) {
        this.entries.delete(id);
      }
    }
  }
}
