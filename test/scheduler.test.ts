import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { RefreshScheduler } from '../src/scheduler.js'

describe('RefreshScheduler', () => {
  beforeEach(() => vi.useFakeTimers())
  afterEach(() => vi.useRealTimers())

  it('fires once at the scheduled time and resets attempts on success', async () => {
    const task = vi.fn(async () => {})
    const s = new RefreshScheduler({ task, onError: () => 'stop' })
    s.scheduleIn(5000)
    await vi.advanceTimersByTimeAsync(4999)
    expect(task).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(1)
    expect(task).toHaveBeenCalledTimes(1)
    expect(s.isActive).toBe(false)
    expect(s.retryAttempt).toBe(0)
  })

  it('scheduleAt uses the injected clock and clamps negative delays to 0', async () => {
    const task = vi.fn(async () => {})
    const s = new RefreshScheduler({ task, onError: () => 'stop', now: () => 1_000_000 })
    s.scheduleAt(999_000)
    await vi.advanceTimersByTimeAsync(0)
    expect(task).toHaveBeenCalledTimes(1)
  })

  it('retries with exponential backoff until success', async () => {
    let calls = 0
    const task = vi.fn(async () => {
      calls++
      if (calls < 4) throw new Error('boom')
    })
    const onError = vi.fn(() => 'retry' as const)
    const s = new RefreshScheduler({ task, onError, minBackoffMs: 1000, maxBackoffMs: 3000 })
    s.scheduleIn(0)
    await vi.advanceTimersByTimeAsync(0)
    expect(calls).toBe(1)
    await vi.advanceTimersByTimeAsync(1000) // attempt 2 after 1s
    expect(calls).toBe(2)
    await vi.advanceTimersByTimeAsync(2000) // attempt 3 after 2s
    expect(calls).toBe(3)
    await vi.advanceTimersByTimeAsync(2999) // attempt 4 capped at 3s
    expect(calls).toBe(3)
    await vi.advanceTimersByTimeAsync(1)
    expect(calls).toBe(4)
    expect(onError).toHaveBeenCalledTimes(3)
    expect(onError).toHaveBeenLastCalledWith(expect.any(Error), 3)
    expect(s.retryAttempt).toBe(0)
    expect(s.isActive).toBe(false)
  })

  it('stops when onError says so', async () => {
    const task = vi.fn(async () => {
      throw new Error('boom')
    })
    const s = new RefreshScheduler({ task, onError: () => 'stop' })
    s.scheduleIn(0)
    await vi.advanceTimersByTimeAsync(10_000)
    expect(task).toHaveBeenCalledTimes(1)
    expect(s.isActive).toBe(false)
  })

  it('cancel disarms the timer and prevents an in-flight task from rescheduling', async () => {
    let resolveTask: (() => void) | undefined
    const task = vi.fn(
      () =>
        new Promise<void>((_, reject) => {
          resolveTask = () => reject(new Error('late failure'))
        }),
    )
    const s = new RefreshScheduler({ task, onError: () => 'retry' })
    s.scheduleIn(0)
    await vi.advanceTimersByTimeAsync(0)
    expect(task).toHaveBeenCalledTimes(1)
    s.cancel()
    resolveTask!()
    await vi.advanceTimersByTimeAsync(120_000)
    expect(task).toHaveBeenCalledTimes(1)
    expect(s.isActive).toBe(false)
  })

  it('a newer schedule replaces an older one', async () => {
    const task = vi.fn(async () => {})
    const s = new RefreshScheduler({ task, onError: () => 'stop' })
    s.scheduleIn(1000)
    s.scheduleIn(5000)
    await vi.advanceTimersByTimeAsync(1000)
    expect(task).not.toHaveBeenCalled()
    await vi.advanceTimersByTimeAsync(4000)
    expect(task).toHaveBeenCalledTimes(1)
  })
})
