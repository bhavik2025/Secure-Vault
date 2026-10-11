export const CLIPBOARD_CLEAR_MS = 30_000

let pending: { timer: ReturnType<typeof setTimeout>; value: string } | null = null

/**
 * Copy text, then try to clear the clipboard after 30 seconds. BEST EFFORT, NOT GUARANTEED:
 * browsers may refuse clipboard access without focus/permission, and the user (or another app) may have
 * copied something else meanwhile. We only clear if the clipboard still holds what we put there, or if
 * we are not allowed to look (in which case we clear rather than risk leaving a secret behind).
 */
export async function copyWithAutoClear(value: string, clearAfterMs = CLIPBOARD_CLEAR_MS): Promise<void> {
  await navigator.clipboard.writeText(value)
  cancelPendingClear()
  const timer = setTimeout(() => {
    void clearIfStillOurs(value)
    pending = null
  }, clearAfterMs)
  pending = { timer, value }
}

async function clearIfStillOurs(value: string): Promise<void> {
  try {
    let current: string | null = null
    try {
      current = await navigator.clipboard.readText()
    } catch {
      current = null // not allowed to read: fall through and clear anyway
    }
    if (current === null || current === value) await navigator.clipboard.writeText('')
  } catch {
    // clearing failed (focus/permission); nothing more we can do
  }
}

export function cancelPendingClear(): void {
  if (pending) clearTimeout(pending.timer)
  pending = null
}
