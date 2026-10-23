"use client";

import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";
import { useEffect, useState } from "react";
import { formatDateTime, timeAgo } from "../lib/format";

/* ── Spinner ───────────────────────────────────────────────── */
export function Spinner({ label = "Loading…" }: { label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm text-ink-3">
      <svg className="h-4 w-4 animate-spin" viewBox="0 0 24 24" fill="none">
        <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="3" opacity="0.25" />
        <path d="M22 12a10 10 0 0 0-10-10" stroke="currentColor" strokeWidth="3" strokeLinecap="round" />
      </svg>
      {label}
    </span>
  );
}

/* ── Surfaces ──────────────────────────────────────────────── */
export function Card({
  children,
  className = "",
  as: Tag = "div",
}: {
  children: React.ReactNode;
  className?: string;
  as?: "div" | "section";
}) {
  return <Tag className={`card p-5 ${className}`}>{children}</Tag>;
}

export function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="mb-3 text-[11px] font-semibold uppercase tracking-[0.08em] text-ink-3">
      {children}
    </h2>
  );
}

/* ── Buttons ───────────────────────────────────────────────── */
const buttonStyles = {
  primary:
    "bg-accent text-[var(--accent-contrast)] hover:opacity-90 shadow-sm",
  secondary:
    "bg-panel text-ink border border-line-strong hover:bg-raised",
  danger:
    "bg-crit/10 text-crit border border-crit/25 hover:bg-crit/15",
  ghost:
    "bg-transparent text-ink-2 border border-transparent hover:bg-raised hover:text-ink",
  success:
    "bg-ok/10 text-ok border border-ok/25 hover:bg-ok/15",
} as const;

export function Button({
  variant = "primary",
  size = "md",
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  variant?: keyof typeof buttonStyles;
  size?: "sm" | "md";
}) {
  const pad = size === "sm" ? "px-2.5 py-1 text-xs" : "px-3 py-1.5 text-sm";
  return (
    <button
      {...props}
      className={`inline-flex items-center gap-1.5 rounded-lg font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${pad} ${buttonStyles[variant]} ${className}`}
    />
  );
}

/* ── Form controls ─────────────────────────────────────────── */
export function Input(props: InputHTMLAttributes<HTMLInputElement>) {
  return <input {...props} className={`input ${props.className ?? ""}`} />;
}

export function Select(props: SelectHTMLAttributes<HTMLSelectElement>) {
  return <select {...props} className={`input ${props.className ?? ""}`} />;
}

export function Textarea(props: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea {...props} className={`input min-h-40 font-mono text-xs ${props.className ?? ""}`} />
  );
}

export function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: React.ReactNode;
  hint?: string;
}) {
  return (
    <label className="block">
      <span className="mb-1 block text-xs font-medium text-ink-2">{label}</span>
      {children}
      {hint ? <span className="mt-1 block text-[11px] text-ink-3">{hint}</span> : null}
    </label>
  );
}

/* ── Badges ────────────────────────────────────────────────── */
const badgeColors = {
  CRITICAL: "bg-crit/10 text-crit border-crit/25",
  HIGH: "bg-high/10 text-high border-high/25",
  MEDIUM: "bg-med/10 text-med border-med/25",
  LOW: "bg-low/10 text-low border-low/25",
  neutral: "bg-[var(--status-info-dim)] text-ink-2 border-line",
  green: "bg-ok/10 text-ok border-ok/25",
  info: "bg-accent-dim text-accent border-accent/25",
  amber: "bg-med/10 text-med border-med/25",
} as const;

export function Badge({
  children,
  color = "neutral",
  className = "",
}: {
  children: React.ReactNode;
  color?: keyof typeof badgeColors;
  className?: string;
}) {
  return (
    <span
      className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[11px] font-medium ${badgeColors[color]} ${className}`}
    >
      {children}
    </span>
  );
}

export function severityColor(sev: string): keyof typeof badgeColors {
  if (sev in badgeColors) return sev as keyof typeof badgeColors;
  return "neutral";
}

/* ── Empty / error states ──────────────────────────────────── */
export function Empty({
  children,
  icon,
}: {
  children: React.ReactNode;
  icon?: React.ReactNode;
}) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-line-strong p-10 text-center text-sm text-ink-3">
      {icon ? <span className="text-ink-3">{icon}</span> : null}
      <div>{children}</div>
    </div>
  );
}

export function ErrorBanner({ message }: { message: string | null | undefined }) {
  if (!message) return null;
  return (
    <div
      role="alert"
      className="rounded-lg border border-crit/25 bg-crit/10 px-3 py-2 text-sm text-crit"
    >
      {message}
    </div>
  );
}

/* ── Hydration-safe relative time ──────────────────────────── */
export function TimeAgo({ date, className = "" }: { date: string; className?: string }) {
  const [label, setLabel] = useState<string | null>(null);
  useEffect(() => {
    const update = () => setLabel(timeAgo(date));
    update();
    const t = setInterval(update, 30_000);
    return () => clearInterval(t);
  }, [date]);
  const absolute = new Date(
    date.endsWith("Z") || date.includes("+") ? date : `${date.replace(" ", "T")}Z`,
  ).toLocaleDateString(undefined, {
    month: "short",
    day: "numeric",
    year: "numeric",
  });
  return <span className={className}>{label ?? absolute}</span>;
}

/* ── Skeleton helpers ──────────────────────────────────────── */
export function Skeleton({ className = "" }: { className?: string }) {
  return <div className={`skeleton ${className}`} />;
}

/* ── Current-time stamp, rendered client-side only ─────────── */
/* Rendering `new Date()` during SSR would desync with hydration. */
export function NowStamp({ className = "" }: { className?: string }) {
  const [stamp, setStamp] = useState<string | null>(null);
  useEffect(() => setStamp(formatDateTime(new Date().toISOString())), []);
  return <span className={className}>{stamp ?? "—"}</span>;
}
