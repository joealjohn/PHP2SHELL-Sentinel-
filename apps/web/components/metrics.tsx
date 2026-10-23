import { ReactNode } from "react";
import { LucideIcon } from "lucide-react";
import type { Finding, Metrics } from "../lib/types";
import { severityLabel } from "../lib/format";
import { TimeAgo } from "./ui";

/* ── Dashboard metric tile ─────────────────────────────────── */
export function DashboardMetric({
  label,
  value,
  delta,
  icon,
  accent = "blue",
  href,
  ariaLabel,
}: {
  label: string;
  value: ReactNode;
  delta?: ReactNode;
  icon: LucideIcon;
  accent?: "blue" | "amber" | "red" | "green";
  href?: string;
  ariaLabel?: string;
}) {
  const accentText = {
    blue: "text-blue-400",
    amber: "text-amber-400",
    red: "text-red-400",
    green: "text-emerald-400",
  }[accent];
  const Icon = icon;
  const Wrapper = ({ children }: { children: ReactNode }) => {
    if (href) {
      return (
        <a href={href} className="card block transition-colors hover:bg-[#111c33]" aria-label={ariaLabel}>
          {children}
        </a>
      );
    }
    return <div className="card">{children}</div>;
  };
  return (
    <Wrapper>
      <div className="flex items-start justify-between p-4 pb-0">
        <span className="text-xs font-medium text-slate-400">{label}</span>
        <Icon className={`h-4 w-4 ${accentText}`} strokeWidth={1.75} aria-hidden />
      </div>
      <div className="flex items-baseline justify-between p-4 pt-1">
        <span className="text-2xl font-semibold text-slate-100">{value}</span>
        {delta ? <span className="text-[11px] text-slate-500">{delta}</span> : null}
      </div>
    </Wrapper>
  );
}

/* ── Documented posture score ──────────────────────────────── */
const WEIGHTS = { CRITICAL: 20, HIGH: 10, MEDIUM: 5, LOW: 2 } as const;

export function postureScore(sev: Metrics["severity"]): number {
  const open =
    seg("CRITICAL") * WEIGHTS.CRITICAL +
    seg("HIGH") * WEIGHTS.HIGH +
    seg("MEDIUM") * WEIGHTS.MEDIUM +
    seg("LOW") * WEIGHTS.LOW;
  return Math.max(0, 100 - open);
  function seg(s: keyof Metrics["severity"]) {
    return sev[s] ?? 0;
  }
}

export function postureBand(score: number): { label: string; color: string } {
  if (score >= 80) return { label: "Good", color: "var(--status-ok)" };
  if (score >= 50) return { label: "Needs attention", color: "var(--sev-medium)" };
  return { label: "Poor", color: "var(--sev-critical)" };
}

export function RiskIndicator({ metrics }: { metrics: Metrics }) {
  const score = postureScore(metrics.severity);
  const band = postureBand(score);
  return (
    <div className="flex flex-col gap-1.5">
      <div className="flex items-center justify-between">
        <span className="text-sm font-medium text-slate-200">
          {score}
          <span className="text-slate-500"> /100</span>
        </span>
        <span className="text-xs" style={{ color: band.color }}>
          {band.label}
        </span>
      </div>
      <div
        className="h-1.5 w-full overflow-hidden rounded-full bg-[rgba(255,255,255,0.06)]"
        role="meter"
        aria-valuenow={score}
        aria-valuemin={0}
        aria-valuemax={100}
        aria-label="Security posture score"
      >
        <div
          className="h-full rounded-full transition-all"
          style={{ width: `${Math.max(score, 1)}%`, background: band.color }}
        />
      </div>
      <p className="text-[11px] leading-4 text-slate-500">
        Derived from open findings, weighted Critical ×20 / High ×10 / Medium ×5 / Low ×2
      </p>
    </div>
  );
}

/* ── Severity overview rows ────────────────────────────────── */
export function SeverityOverview({ metrics }: { metrics: Metrics }) {
  const total = SEVS.reduce((a, s) => a + (metrics.severity[s] ?? 0), 0);
  const max = Math.max(1, ...SEVS.map((s) => metrics.severity[s] ?? 0));
  return (
    <div className="flex flex-col gap-3">
      {SEVS.map((sev) => {
        const count = metrics.severity[sev] ?? 0;
        return (
          <a
            key={sev}
            href={`/findings?severity=${sev}&status=OPEN%2COPEN_RISK_ACCEPTED%2COPEN_TRACKED`}
            className="group grid grid-cols-[72px_1fr_28px] items-center gap-3"
            title={`${count} open ${severityLabel[sev]} finding${count === 1 ? "" : "s"} — view`}
          >
            <span className="text-xs font-medium text-slate-300">{severityLabel[sev]}</span>
            <span className="h-2.5 overflow-hidden rounded-full bg-[rgba(255,255,255,0.05)]">
              <span
                className="block h-full rounded-full transition-all"
                style={{
                  width: `${Math.max((count / max) * 100, count > 0 ? 3 : 0)}%`,
                  background: SEV_COLOR[sev],
                }}
              />
            </span>
            <span className="text-right text-xs font-semibold tabular-nums text-slate-200">
              {count}
            </span>
          </a>
        );
      })}
      {total === 0 ? (
        <p className="text-xs text-slate-500">No open findings right now.</p>
      ) : null}
    </div>
  );
}

const SEVS = ["CRITICAL", "HIGH", "MEDIUM", "LOW"] as const;

const SEV_COLOR: Record<(typeof SEVS)[number], string> = {
  CRITICAL: "var(--sev-critical)",
  HIGH: "var(--sev-high)",
  MEDIUM: "var(--sev-medium)",
  LOW: "var(--sev-low)",
};

/* ── Activity feed item ────────────────────────────────────── */
export function ActivityItem({
  icon: Icon,
  children,
  when,
  unread,
}: {
  icon: LucideIcon;
  children: ReactNode;
  when?: string;
  unread?: boolean;
}) {
  return (
    <li className="flex items-start gap-3 py-2.5">
      <span
        className={`mt-0.5 flex h-6 w-6 shrink-0 items-center justify-center rounded-md border ${
          unread
            ? "border-[rgba(52,211,153,0.35)] bg-[var(--status-ok-dim)] text-[var(--status-ok)]"
            : "border-[rgba(255,255,255,0.08)] bg-[var(--bg-raised)] text-slate-500"
        }`}
      >
        <Icon className="h-3 w-3" strokeWidth={1.75} aria-hidden />
      </span>
      <div className="min-w-0 flex-1 text-sm text-slate-300">{children}</div>
      {when ? (
        <TimeAgo date={when} className="shrink-0 text-[11px] text-slate-500" />
      ) : null}
    </li>
  );
}

/* ── Finding row helper (dashboard feed) ───────────────────── */
export function recentFindingHref(f: Pick<Finding, "id" | "status" | "severity">): string {
  return `/findings/${f.id}`;
}
