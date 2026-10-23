"use client";

import { useMemo } from "react";
import { formatDateTime, scanStatusLabel } from "../lib/format";
import type { Scan } from "../lib/types";

type Day = { date: string; completed: number; failed: number; other: number };

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
export function scanDays(scans: Scan[], days = 14): Day[] {
  const dates = lastNDays(days);
  const map = new Map<string, Day>(dates.map((d) => [d, { date: d, completed: 0, failed: 0, other: 0 }]));
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

export function ScanActivityChart({
  days,
  height = 140,
  ariaLabel = "Scan activity over the last 14 days",
}: {
  days: Day[];
  height?: number;
  ariaLabel?: string;
}) {
  const W = days.length * 34 + 20;
  const H = 180;

  const max = useMemo(
    () =>
      Math.max(
        4,
        ...days.map((d) => d.completed + d.failed + d.other),
      ),
    [days],
  );

  const labels = useMemo(() => {
    const idx = days.length / 2;
    return days.map((d, i) => {
      const dt = new Date(`${d.date}T00:00:00Z`);
      return i % 2 === 0 || Math.abs(i - idx) < 1
        ? dt.toLocaleDateString(undefined, { month: "short", day: "numeric" })
        : "";
    });
  }, [days]);

  const anyActivity = days.some((d) => d.completed + d.failed + d.other > 0);

  return (
    <figure>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        width="100%"
        height={height}
        role="img"
        aria-label={ariaLabel}
        preserveAspectRatio="xMidYMid meet"
      >
        <line
          x1="10"
          y1={H - 22}
          x2={W - 10}
          y2={H - 22}
          stroke="rgba(255,255,255,0.12)"
          strokeWidth="1"
        />
        {anyActivity
          ? days.map((d, i) => {
              const x = 22 + i * 34;
              const total = d.completed + d.failed + d.other;
              if (total === 0) {
                return (
                  <rect key={d.date} x={x} y={H - 24} width="18" height="2" rx="1" fill="rgba(148,163,184,0.15)">
                    <title>{`${d.date}: no scans`}</title>
                  </rect>
                );
              }
              const barH = 4 + Math.round(((total) / max) * 108);
              const y = H - 22 - barH;
              const failedH = d.failed ? Math.max(4, Math.round((d.failed / total) * barH)) : 0;
              return (
                <g key={d.date}>
                  <rect x={x} y={y} width="18" height={barH} rx="3" fill="var(--status-ok-dim)" stroke="rgba(52,211,153,0.35)" strokeWidth="1">
                    <title>{`${d.date}: ${scanStatusLabel.COMPLETED} ${d.completed}, ${scanStatusLabel.FAILED} ${d.failed}${d.other ? `, in progress ${d.other}` : ""} — updated ${formatDateTime(d.date)}`}</title>
                  </rect>
                  {failedH > 0 ? (
                    <rect
                      x={x}
                      y={y + barH - failedH}
                      width="18"
                      height={failedH}
                      rx="3"
                      fill="var(--sev-critical-dim)"
                      stroke="rgba(248,113,113,0.4)"
                      strokeWidth="1"
                    />
                  ) : null}
                  <text
                    x={x + 9}
                    y={H - 6}
                    textAnchor="middle"
                    fontSize="9"
                    fill="var(--text-muted)"
                    fontFamily="inherit"
                  >
                    {labels[i]}
                  </text>
                </g>
              );
            })
          : null}
      </svg>
      <figcaption className="mt-1 flex items-center gap-4 text-[11px] text-slate-500">
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-sm border border-[rgba(52,211,153,0.4)] bg-[var(--status-ok-dim)]" />
          Completed
        </span>
        <span className="flex items-center gap-1.5">
          <span className="h-2 w-2 rounded-sm border border-[rgba(248,113,113,0.4)] bg-[var(--sev-critical-dim)]" />
          Failed
        </span>
      </figcaption>
    </figure>
  );
}
