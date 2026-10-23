"use client";

import { useMemo } from "react";
import { formatDateTime, scanStatusLabel } from "../lib/format";
import type { Scan } from "../lib/types";

type Day = { date: string; completed: number; failed: number; other: number };

const DAYS = 14;

function lastNDays(n: number): string[] {
  const out: string[] = [];
  const today = new Date();
  for (let i = n - 1; i >= 0; i--) {
    const d = new Date(today.getTime() - i * 86_400_000);
    out.push(d.toISOString().slice(0, 10));
  }
  return out;
}

/**
 * Real scan history aggregated client-side from the live scans list
 * (GET /api/scans). Green = completed runs, red = failed runs.
 */
export function scanDays(scans: Scan[], days = DAYS): Day[] {
  const dates = lastNDays(days);
  const map = new Map<string, Day>(
    dates.map((d) => [d, { date: d, completed: 0, failed: 0, other: 0 }]),
  );
  for (const s of scans) {
    const k = String(s.created_at).slice(0, 10);
    const day = map.get(k);
    if (!day) continue;
    if (s.status === "COMPLETED") day.completed += 1;
    else if (s.status === "FAILED") day.failed += 1;
    else day.other += 1;
  }
  return [...map.values()];
}

function dayLabel(date: string): string {
  return new Date(`${date}T00:00:00Z`).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
  });
}

export function ScanActivityChart({
  days,
  height = 140,
  ariaLabel = "Scan activity over the last 14 days",
}: {
  days: Day[];
  height?: number;
  ariaLabel?: string;
}) {
  const max = useMemo(
    () => Math.max(1, ...days.map((d) => d.completed + d.failed + d.other)),
    [days],
  );
  const anyActivity = days.some((d) => d.completed + d.failed + d.other > 0);
  const barArea = Math.max(40, height - 22);

  if (!anyActivity) {
    return (
      <div
        className="flex items-center justify-center rounded-lg border border-dashed border-line-strong text-xs text-ink-3"
        style={{ height }}
      >
        No scan activity in the last {days.length} days.
      </div>
    );
  }

  return (
    <figure>
      <div
        className="flex items-end gap-1.5"
        style={{ height }}
        role="img"
        aria-label={ariaLabel}
      >
        {days.map((d, i) => {
          const total = d.completed + d.failed + d.other;
          const barH = total
            ? Math.max(6, Math.round((total / max) * barArea))
            : 2;
          const failedPct = total && d.failed ? Math.round((d.failed / total) * 100) : 0;
          return (
            <div
              key={d.date}
              className="flex h-full flex-1 flex-col items-center justify-end"
              title={
                total
                  ? `${dayLabel(d.date)}: ${scanStatusLabel.COMPLETED} ${d.completed}, ${scanStatusLabel.FAILED} ${d.failed}${d.other ? `, in progress ${d.other}` : ""} — ${formatDateTime(d.date)}`
                  : `${dayLabel(d.date)}: no scans`
              }
            >
              <div
                className={`relative w-full max-w-[20px] overflow-hidden rounded-[3px] ${
                  total
                    ? "border border-ok/35 bg-ok/15"
                    : "bg-line-strong"
                }`}
                style={{ height: barH }}
              >
                {failedPct > 0 ? (
                  <div
                    className="absolute inset-x-0 bottom-0 border-t border-crit/50 bg-crit/25"
                    style={{ height: `${failedPct}%` }}
                  />
                ) : null}
              </div>
              <span
                className={`mt-1.5 h-3 text-[9px] leading-3 text-ink-3 ${
                  i % 2 === 0 ? "" : "opacity-0"
                }`}
                aria-hidden
              >
                {dayLabel(d.date)}
              </span>
            </div>
          );
        })}
      </div>
      <figcaption className="mt-1 flex items-center gap-4 text-[11px] text-ink-3">
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-sm border border-ok/40 bg-ok/10" />
          Completed
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-sm border border-crit/40 bg-crit/10" />
          Failed
        </span>
      </figcaption>
    </figure>
  );
}
