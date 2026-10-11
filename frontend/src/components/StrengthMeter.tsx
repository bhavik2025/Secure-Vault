import type { Strength } from '../lib/types'

const LABELS: Record<string, { text: string; width: string; color: string }> = {
  VERY_WEAK: { text: 'Very weak', width: 'w-1/5', color: 'bg-red-500' },
  WEAK: { text: 'Weak', width: 'w-2/5', color: 'bg-orange-500' },
  FAIR: { text: 'Fair', width: 'w-3/5', color: 'bg-amber-500' },
  STRONG: { text: 'Strong', width: 'w-4/5', color: 'bg-lime-500' },
  VERY_STRONG: { text: 'Very strong', width: 'w-full', color: 'bg-emerald-500' },
}

/** Shows the server's entropy estimate. It is a heuristic upper bound, and the UI says so. */
export function StrengthMeter({ strength }: { strength: Pick<Strength, 'bits' | 'label'> | null }) {
  if (!strength) return null
  const l = LABELS[strength.label] ?? LABELS.VERY_WEAK
  return (
    <div>
      <div className="h-2 w-full overflow-hidden rounded-full bg-slate-200 dark:bg-slate-700">
        <div className={`h-full ${l.width} ${l.color}`} />
      </div>
      <p className="mt-1 text-xs text-slate-600 dark:text-slate-300" aria-live="polite">
        {l.text} · about {Math.round(strength.bits)} bits of entropy (estimate)
      </p>
    </div>
  )
}
