/**
 * Single-timer scheduler for background token refresh with exponential
 * backoff. Knows nothing about OAuth; the client supplies the task and the
 * retry policy.
 */

export interface RefreshSchedulerOptions {
  /** The work to run when the timer fires (a token refresh). */
  task: () => Promise<void>
  /**
   * Called when `task` rejects. Return `'retry'` to schedule another attempt
   * with backoff, or `'stop'` to give up until `scheduleIn`/`scheduleAt` is
   * called again. `attempt` starts at 1.
   */
  onError: (error: unknown, attempt: number) => 'retry' | 'stop'
  /** First retry delay. Default 1000 ms. */
  minBackoffMs?: number | undefined
  /** Cap on retry delay. Default 60 000 ms. */
  maxBackoffMs?: number | undefined
  /** Clock, injectable for tests. Default `Date.now`. */
  now?: (() => number) | undefined
}

/** Largest delay `setTimeout` accepts without overflowing to 1 ms. */
const MAX_TIMEOUT_MS = 2_147_483_647

type TimerHandle = ReturnType<typeof setTimeout>

export class RefreshScheduler {
  private timer: TimerHandle | null = null
  private attempt = 0
  private running = false
  /** Bumped on cancel() so a task that was already in flight cannot reschedule. */
  private generation = 0
  private readonly minBackoffMs: number
  private readonly maxBackoffMs: number
  private readonly now: () => number

  constructor(private readonly options: RefreshSchedulerOptions) {
    this.minBackoffMs = options.minBackoffMs ?? 1_000
    this.maxBackoffMs = options.maxBackoffMs ?? 60_000
    this.now = options.now ?? Date.now
  }

  /** True while a timer is armed or the task is executing. */
  get isActive(): boolean {
    return this.timer !== null || this.running
  }

  /** Current retry attempt (0 when the last run succeeded or nothing ran yet). */
  get retryAttempt(): number {
    return this.attempt
  }

  /** Arm the timer to fire at an absolute epoch-ms time. Replaces any armed timer and resets backoff. */
  scheduleAt(epochMs: number): void {
    this.attempt = 0
    this.arm(epochMs - this.now())
  }

  /** Arm the timer to fire after `delayMs`. Replaces any armed timer and resets backoff. */
  scheduleIn(delayMs: number): void {
    this.attempt = 0
    this.arm(delayMs)
  }

  /** Disarm the timer. A task already in flight finishes but will not reschedule. */
  cancel(): void {
    this.generation++
    this.attempt = 0
    if (this.timer !== null) {
      clearTimeout(this.timer)
      this.timer = null
    }
  }

  /** Delay before retry number `attempt` (1-based): min * 2^(attempt-1), capped. */
  backoffFor(attempt: number): number {
    const exp = Math.min(attempt - 1, 30)
    return Math.min(this.minBackoffMs * 2 ** exp, this.maxBackoffMs)
  }

  private arm(delayMs: number): void {
    if (this.timer !== null) clearTimeout(this.timer)
    const generation = this.generation
    const delay = Math.min(Math.max(0, Math.floor(delayMs)), MAX_TIMEOUT_MS)
    const handle = setTimeout(() => {
      this.timer = null
      void this.fire(generation)
    }, delay)
    // Do not keep a Node/Bun process alive just for a refresh timer.
    const maybeUnref = handle as unknown as { unref?: () => void }
    if (typeof maybeUnref.unref === 'function') maybeUnref.unref()
    this.timer = handle
  }

  private async fire(generation: number): Promise<void> {
    this.running = true
    try {
      await this.options.task()
      if (generation === this.generation) this.attempt = 0
    } catch (error) {
      if (generation !== this.generation) return
      this.attempt++
      let decision: 'retry' | 'stop'
      try {
        decision = this.options.onError(error, this.attempt)
      } catch {
        decision = 'stop'
      }
      if (decision === 'retry' && generation === this.generation && this.timer === null) {
        this.arm(this.backoffFor(this.attempt))
      }
    } finally {
      this.running = false
    }
  }
}
